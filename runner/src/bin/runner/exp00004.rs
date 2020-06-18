//! Run a memcached workload on the remote test machine designed to induce THP compaction
//! remotely. Measure the number of per-page operations done and undone. Unlike exp00003, run
//! this on the bare-metal host, rather than in a VM.
//!
//! Requires `setup00000` with the `markm_instrument_thp_compaction` branch, no VM needed.

use clap::clap_app;

use runner::{
    dir,
    exp_0sim::*,
    get_user_home_dir,
    output::{Parametrize, Timestamp},
    paths::*,
    time,
    workloads::{run_memcached_and_capture_thp, MemcachedWorkloadConfig, TasksetCtx},
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

/// Interval at which to collect thp stats
const INTERVAL: usize = 60; // seconds

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    size: usize,

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
    fn is_usize(s: String) -> Result<(), String> {
        s.as_str()
            .parse::<usize>()
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }

    clap_app! { exp00004 =>
        (about: "Run experiment 00004. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg SIZE: +required +takes_value {is_usize}
         "The number of GBs of the workload (e.g. 500)")
    }
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };
    let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();

    let ushell = SshShell::with_default_key(&login.username, &login.host)?;
    let local_git_hash = runner::local_research_workspace_git_hash()?;
    let remote_git_hash = runner::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = runner::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (4, "memcached_thp_ops_per_page_bare_metal".into()),

        size,

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
    initial_reboot_no_vagrant(&login)?;

    // Connect
    let ushell = connect_and_setup_host_only(&login)?;

    let user_home = &get_user_home_dir(&ushell)?;
    let zerosim_exp_path = &dir!(
        user_home.as_str(),
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );

    // Collect timers on VM
    let mut timers = vec![];

    let (output_file, params_file, time_file, _sim_file) = cfg.gen_standard_names();
    let params = serde_json::to_string(&cfg)?;

    ushell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(
            user_home.as_str(),
            setup00000::HOSTNAME_SHARED_RESULTS_DIR,
            params_file
        )
    ))?;

    ushell.run(cmd!("sudo swapon /dev/sda3"))?;

    // Turn on compaction and force it to happen
    runner::turn_on_thp(
        &ushell,
        &cfg.transparent_hugepage_enabled,
        &cfg.transparent_hugepage_defrag,
        cfg.transparent_hugepage_khugepaged_defrag,
        cfg.transparent_hugepage_khugepaged_alloc_sleep_ms,
        cfg.transparent_hugepage_khugepaged_scan_sleep_ms,
    )?;

    let cores = runner::get_num_cores(&ushell)?;
    let mut tctx = TasksetCtx::new(cores);

    // Run workload
    time!(
        timers,
        "Setup and Workload",
        run_memcached_and_capture_thp(
            &ushell,
            &MemcachedWorkloadConfig {
                user: login.username,
                exp_dir: zerosim_exp_path,
                memcached: &dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_MEMCACHED_SUBMODULE),
                server_size_mb: cfg.size << 10,
                wk_size_gb: cfg.size,
                allow_oom: true,
                output_file: None,
                eager: None,
                client_pin_core: tctx.next(),
                server_pin_core: None,
                freq: None,
                pf_time: None,
                pintool: None,
                damon: None,
            },
            INTERVAL,
            /* continual_compaction */ None,
            &dir!(setup00000::HOSTNAME_SHARED_RESULTS_DIR, output_file),
        )?
    );

    ushell.run(cmd!("date"))?;

    ushell.run(cmd!("free -h"))?;

    ushell.run(cmd!(
        "echo -e '{}' > {}",
        runner::timings_str(timers.as_slice()),
        dir!(setup00000::HOSTNAME_SHARED_RESULTS_DIR, time_file)
    ))?;

    let glob = cfg.gen_file_name("*");
    println!(
        "RESULTS: {}",
        dir!(setup00000::HOSTNAME_SHARED_RESULTS_DIR, glob)
    );

    Ok(())
}
