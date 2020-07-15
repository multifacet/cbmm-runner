//! Run a memcached workload on the remote host (in simulation) in the presence of aggressive
//! kernel memory compaction.
//!
//! This workload has two alternative modes:
//! 1) Enable THP compaction and set kcompactd to run aggressively.
//! 2) Induce continual compaction by causing spurious failures in the compaction algo.
//!
//! Run a memcached workload on the remote test machine designed to induce THP compaction remotely.
//! Measure the latency of the workload and the number of per-page operations done and undone.
//!
//! Requires `setup00000` followed by `setup00001`.

use clap::clap_app;

use runner::{
    cli::validator,
    dir,
    exp_0sim::*,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    time,
    workloads::{run_memcached_and_capture_thp, MemcachedWorkloadConfig, TasksetCtx},
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

use crate::setup00001::GUEST_SWAP_GBS;

/// Interval at which to collect thp stats
const INTERVAL: usize = 60; // seconds

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    continual_compaction: Option<usize>,

    #[name]
    size: usize,
    calibrate: bool,

    #[name]
    vm_size: usize,
    #[name]
    cores: usize,

    zswap_max_pool_percent: usize,

    transparent_hugepage_enabled: String,
    transparent_hugepage_defrag: String,
    transparent_hugepage_khugepaged_defrag: usize,
    transparent_hugepage_khugepaged_alloc_sleep_ms: usize,
    transparent_hugepage_khugepaged_scan_sleep_ms: usize,

    username: String,
    host: String,

    local_git_hash: String,
    remote_git_hash: String,

    remote_research_settings: std::collections::BTreeMap<String, String>,

    #[timestamp]
    timestamp: Timestamp,
}

pub fn cli_options() -> clap::App<'static, 'static> {
    clap_app! { exp00003 =>
        (about: "Run experiment 00003. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg VMSIZE: +required +takes_value {validator::is::<usize>}
         "The number of GBs of the VM (e.g. 500)")
        (@arg CORES: -C --cores +takes_value {validator::is::<usize>}
         "(Optional) The number of cores of the VM (defaults to 1)")
        (@arg SIZE: -s --size +takes_value {validator::is::<usize>}
         "(Optional) The number of GBs of the workload (e.g. 500). Defaults to VMSIZE + 10")
        (@arg CONTINUAL: --continual_compaction +takes_value {validator::is::<usize>}
         "(Optional) Enables continual compaction via spurious failures of the given mode")
    }
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };
    let vm_size = sub_m.value_of("VMSIZE").unwrap().parse::<usize>().unwrap();

    let size = if let Some(size) = sub_m
        .value_of("SIZE")
        .map(|value| value.parse::<usize>().unwrap())
    {
        size
    } else {
        // Just a bit smaller so we don't OOM
        vm_size + GUEST_SWAP_GBS - 1
    };

    let cores = if let Some(cores) = sub_m
        .value_of("CORES")
        .map(|value| value.parse::<usize>().unwrap())
    {
        cores
    } else {
        VAGRANT_CORES
    };

    let continual_compaction = sub_m
        .value_of("CONTINUAL")
        .map(|value| value.parse::<usize>().unwrap());

    let ushell = SshShell::with_default_key(&login.username, &login.host)?;
    let local_git_hash = runner::local_research_workspace_git_hash()?;
    let remote_git_hash = runner::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = runner::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (3, "memcached_per_page_thp_ops".into()),

        continual_compaction,

        size,
        calibrate: false,

        vm_size,
        cores,

        zswap_max_pool_percent: 50,

        transparent_hugepage_enabled: "always".into(),
        transparent_hugepage_defrag: "always".into(),
        transparent_hugepage_khugepaged_defrag: 1,
        transparent_hugepage_khugepaged_alloc_sleep_ms: 1000,
        transparent_hugepage_khugepaged_scan_sleep_ms: 1000,

        username: login.username.into(),
        host: login.hostname.into(),

        local_git_hash,
        remote_git_hash,

        remote_research_settings,

        timestamp: Timestamp::now(),
    };

    run_inner(&login, &cfg)
}

fn run_inner<A>(login: &Login<A>, cfg: &Config) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Reboot
    initial_reboot(&login)?;

    // Collect timers on VM
    let mut timers = vec![];

    // Connect
    let (mut ushell, vshell) = time!(
        timers,
        "Setup host and start VM",
        connect_and_setup_host_and_vagrant(
            &login,
            cfg.vm_size,
            cfg.cores,
            ZEROSIM_SKIP_HALT,
            ZEROSIM_LAPIC_ADJUST
        )?
    );

    // Environment
    ZeroSim::turn_on_zswap(&mut ushell)?;
    ZeroSim::zswap_max_pool_percent(&ushell, cfg.zswap_max_pool_percent)?;

    // Mount guest swap space
    let research_settings = runner::get_remote_research_settings(&ushell)?;
    let guest_swap: &str =
        runner::get_remote_research_setting(&research_settings, "guest_swap")?.unwrap();
    vshell.run(cmd!("sudo swapon {}", guest_swap))?;

    let zerosim_exp_path = &dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );

    // Calibrate
    if cfg.calibrate {
        time!(
            timers,
            "Calibrate",
            vshell.run(cmd!("sudo ./target/release/time_calibrate").cwd(zerosim_exp_path))?
        );
    }

    let (output_file, params_file, time_file, sim_file) = cfg.gen_standard_names();
    let memcached_timing_file = cfg.gen_file_name("memcached_latency");
    let params = serde_json::to_string(&cfg)?;

    vshell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(VAGRANT_RESULTS_DIR, params_file)
    ))?;

    // Turn on compaction and force it too happen
    runner::turn_on_thp(
        &vshell,
        &cfg.transparent_hugepage_enabled,
        &cfg.transparent_hugepage_defrag,
        cfg.transparent_hugepage_khugepaged_defrag,
        cfg.transparent_hugepage_khugepaged_alloc_sleep_ms,
        cfg.transparent_hugepage_khugepaged_scan_sleep_ms,
    )?;

    let mut tctx = TasksetCtx::new(cfg.cores);

    time!(
        timers,
        "Start and Workload",
        run_memcached_and_capture_thp(
            &vshell,
            &MemcachedWorkloadConfig {
                user: "vagrant",
                exp_dir: zerosim_exp_path,
                memcached: &dir!(
                    "/home/vagrant",
                    RESEARCH_WORKSPACE_PATH,
                    ZEROSIM_MEMCACHED_SUBMODULE
                ),
                server_size_mb: cfg.size << 10,
                wk_size_gb: cfg.size,
                allow_oom: false,
                output_file: Some(&dir!(VAGRANT_RESULTS_DIR, memcached_timing_file)),
                eager: None,
                client_pin_core: tctx.next(),
                server_pin_core: None,
                freq: None,
                pf_time: None,
                pintool: None,
                damon: None,
                mmu_perf: None,
                server_start_cb: |_| Ok(()),
            },
            INTERVAL,
            cfg.continual_compaction,
            &dir!(VAGRANT_RESULTS_DIR, output_file),
        )?
    );

    ushell.run(cmd!("date"))?;

    vshell.run(cmd!(
        "echo -e '{}' > {}",
        runner::timings_str(timers.as_slice()),
        dir!(VAGRANT_RESULTS_DIR, time_file)
    ))?;

    runner::exp_0sim::gen_standard_sim_output(&sim_file, &ushell, &vshell)?;

    let glob = cfg.gen_file_name("*");
    println!("RESULTS: {}", dir!(HOSTNAME_SHARED_RESULTS_DIR, glob));

    Ok(())
}
