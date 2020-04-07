//! Run the given YCSB workload on the remote machine in simulation and record its results.
//!
//! Requires `setup00000`. If `--mmstats` is used, then `setup00002` with an instrumented kernel is
//! needed.

use clap::clap_app;

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

use crate::common::{
    exp_0sim::*,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    workloads::{
        run_ycsb_workload, MemcachedWorkloadConfig, Pintool, YcsbConfig, YcsbSystem, YcsbWorkload,
    },
};

pub const PERIOD: usize = 10; // seconds

#[derive(Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    workload: YcsbWorkload,
    #[name]
    system: YcsbSystem,

    #[name]
    vm_size: usize,
    #[name(self.cores > 1)]
    cores: usize,

    memtrace: bool,
    mmstats: bool,
    mmstats_periodic: bool,

    transparent_hugepage_enabled: String,
    transparent_hugepage_defrag: String,
    transparent_hugepage_khugepaged_defrag: usize,
    transparent_hugepage_khugepaged_alloc_sleep_ms: usize,
    transparent_hugepage_khugepaged_scan_sleep_ms: usize,

    zswap_max_pool_percent: usize,

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

    clap_app! { exp00011 =>
        (about: "Run experiment 00011. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg VMSIZE: +required +takes_value {is_usize}
         "The number of GBs of the VM (e.g. 500)")
        (@arg CORES: +required +takes_value {is_usize}
         "The number of cores of the VM")
        (@group WORKLOAD =>
            (@attributes +required)
            (@arg WKA: --a
             "Run YCSB core workload A.")
            (@arg WKB: --b
             "Run YCSB core workload B.")
            (@arg WKC: --c
             "Run YCSB core workload C.")
            (@arg WKD: --d
             "Run YCSB core workload D.")
            (@arg WKE: --e
             "Run YCSB core workload E.")
            (@arg WKF: --f
             "Run YCSB core workload F.")
        )
        (@group SYSTEM =>
            (@attributes +required)
            (@arg MEMCACHED: --memcached
             "Use memcached as the YCSB backend.")
            (@arg REDIS: --redis
             "Use redis as the YCSB backend.")
            (@arg KC: --kyotocabinet
             "Use kyotocabinet as the YCSB backend.")
        )
        (@arg MEMTRACE: --memtrace
         "Collect a memory trace of the given system.")
        (@arg MMSTATS: --mmstats
         "Collect kernel memory management stats.")
        (@arg PERIODIC: --periodic requires[MMSTATS]
         "Collect kernel memory management stats periodically.")
    }
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let vm_size = sub_m.value_of("VMSIZE").unwrap().parse::<usize>().unwrap();
    let cores = sub_m.value_of("CORES").unwrap().parse::<usize>().unwrap();

    let workload = match () {
        () if sub_m.is_present("WKA") => YcsbWorkload::A,
        () if sub_m.is_present("WKB") => YcsbWorkload::B,
        () if sub_m.is_present("WKC") => YcsbWorkload::C,
        () if sub_m.is_present("WKD") => YcsbWorkload::D,
        () if sub_m.is_present("WKE") => YcsbWorkload::E,
        () if sub_m.is_present("WKF") => YcsbWorkload::F,
        _ => unreachable!(),
    };

    let system = match () {
        () if sub_m.is_present("MEMCACHED") => YcsbSystem::Memcached,
        () if sub_m.is_present("REDIS") => YcsbSystem::Redis,
        () if sub_m.is_present("KC") => YcsbSystem::KyotoCabinet,
        _ => unreachable!(),
    };

    let memtrace = sub_m.is_present("MEMTRACE");
    let mmstats = sub_m.is_present("MMSTATS");
    let periodic = sub_m.is_present("PERIODIC");

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = crate::common::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::common::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::common::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (11, "ycsb".into()),

        workload,
        system,

        vm_size,
        cores,

        memtrace,
        mmstats,
        mmstats_periodic: periodic,

        transparent_hugepage_enabled: "always".into(),
        transparent_hugepage_defrag: "always".into(),
        transparent_hugepage_khugepaged_defrag: 1,
        transparent_hugepage_khugepaged_alloc_sleep_ms: 60000, // Default Linux value
        transparent_hugepage_khugepaged_scan_sleep_ms: 10000,  // Default Linux value

        zswap_max_pool_percent: 50,

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

    // Connect to host
    let mut ushell = connect_and_setup_host_only(&login)?;

    // Turn on SSDSWAP.
    turn_on_ssdswap(&ushell)?;

    // Collect timers on VM
    let mut timers = vec![];

    // Start and connect to VM
    let vshell = time!(
        timers,
        "Start VM",
        start_vagrant(
            &ushell,
            &login.host,
            cfg.vm_size,
            cfg.cores,
            /* fast */ true,
            ZEROSIM_SKIP_HALT,
            ZEROSIM_LAPIC_ADJUST,
        )?
    );

    // Environment
    ZeroSim::turn_on_zswap(&mut ushell)?;
    ZeroSim::zswap_max_pool_percent(&ushell, cfg.zswap_max_pool_percent)?;

    let zerosim_exp_path = &dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );

    // Turn on THP.
    crate::common::turn_on_thp(
        &vshell,
        &cfg.transparent_hugepage_enabled,
        &cfg.transparent_hugepage_defrag,
        cfg.transparent_hugepage_khugepaged_defrag,
        cfg.transparent_hugepage_khugepaged_alloc_sleep_ms,
        cfg.transparent_hugepage_khugepaged_scan_sleep_ms,
    )?;

    // Get the amount of memory the guest thinks it has (in GB).
    let size = vshell
        .run(cmd!("grep MemAvailable /proc/meminfo | awk '{{print $2}}'").use_bash())?
        .stdout
        .trim()
        .parse::<usize>()
        .unwrap()
        >> 20;

    let (_output_file, params_file, time_file, sim_file) = cfg.gen_standard_names();
    let params = serde_json::to_string(&*cfg)?;
    vshell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(VAGRANT_RESULTS_DIR, params_file)
    ))?;

    let pin_path = dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_MEMBUFFER_EXTRACT_SUBMODULE,
        "pin"
    );
    let trace_file = dir!(VAGRANT_RESULTS_DIR, cfg.gen_file_name("trace"));
    let mmstats_file = cfg.gen_file_name("mmstats");

    // Set histogram parameters before workload.
    let maybe_shell_and_handle = if cfg.mmstats && !cfg.mmstats_periodic {
        // Print the current numbers, 'cause why not?
        vshell.run(cmd!("tail /proc/mm_*"))?;

        // Writing to any of the params will reset the plot.
        vshell.run(cmd!(
            "for h in /proc/mm_*_min ; do echo $h ; echo 0 | sudo tee $h ; done"
        ))?;

        None
    } else if cfg.mmstats_periodic {
        // Read and reset stats over PERIOD seconds.
        let vshell2 = connect_to_vagrant_as_root(login.hostname)?;
        let ret = vshell2.spawn(
            cmd!(
                "while [ ! -e /tmp/exp-stop ] ; do \
                 tail /proc/mm_* | tee -a {} ; \
                 for h in /proc/mm_*_min ; do echo $h ; echo 0 | sudo tee $h ; done \
                 sleep {} ; \
                 done ; echo done measuring",
                dir!(VAGRANT_RESULTS_DIR, &mmstats_file),
                PERIOD
            )
            .use_bash(),
        )?;

        // Wait to make sure the collection of stats has started
        vshell2.run(
            cmd!(
                "while [ ! -e {} ] ; do sleep 1 ; done",
                dir!(VAGRANT_RESULTS_DIR, &mmstats_file),
            )
            .use_bash(),
        )?;

        Some((vshell2, ret))
    } else {
        None
    };

    // TODO: support for redis and kc

    // Run the workload.
    time!(
        timers,
        "Workload",
        run_ycsb_workload::<spurs::SshError, _>(
            &vshell,
            YcsbConfig {
                workload: cfg.workload,
                system: cfg.system,
                ycsb_path: &dir!(
                    "/home/vagrant",
                    RESEARCH_WORKSPACE_PATH,
                    ZEROSIM_YCSB_SUBMODULE
                ),
                memcached: Some(MemcachedWorkloadConfig {
                    user: "vagrant",
                    exp_dir: zerosim_exp_path,
                    memcached: &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_MEMCACHED_SUBMODULE
                    ),
                    allow_oom: false, // evict data
                    server_pin_core: None,
                    server_size_mb: size << 10,
                    pintool: if cfg.memtrace {
                        Some(Pintool::MemTrace {
                            pin_path: &pin_path,
                            output_path: &trace_file,
                        })
                    } else {
                        None
                    },

                    // Ignored:
                    wk_size_gb: 0,
                    freq: None,
                    pf_time: None,
                    output_file: None,
                    eager: false,
                    client_pin_core: 0,
                }),
                callback: || {
                    // If we are taking a trace, sleep for 10 seconds to hopefully make a noticable
                    // mark in the trace data.
                    if cfg.memtrace {
                        std::thread::sleep(std::time::Duration::from_secs(10));
                    }

                    // If we are collecting memory stats, reset them now.
                    if cfg.mmstats {
                        // Print the current numbers, 'cause why not?
                        vshell.run(cmd!("tail /proc/mm_*"))?;

                        // Writing to any of the params will reset the plot.
                        vshell.run(cmd!(
                            "for h in /proc/mm_*_min ; do echo $h ; echo 0 | sudo tee $h ; done"
                        ))?;
                    }

                    Ok(())
                },
            }
        )?
    );

    // Collect stats after the workload runs.
    if cfg.mmstats && !cfg.mmstats_periodic {
        vshell.run(cmd!(
            "tail /proc/mm_* | tee {}",
            dir!(VAGRANT_RESULTS_DIR, &mmstats_file)
        ))?;
        vshell.run(cmd!(
            "cat /proc/meminfo | tee -a {}",
            dir!(VAGRANT_RESULTS_DIR, &mmstats_file)
        ))?;
        vshell.run(cmd!(
            "cat /proc/vmstat | tee -a {}",
            dir!(VAGRANT_RESULTS_DIR, &mmstats_file)
        ))?;
    } else if cfg.mmstats_periodic {
        vshell.run(cmd!("touch /tmp/exp-stop"))?;
        time!(
            timers,
            "Waiting for mmstats thread to halt",
            maybe_shell_and_handle.unwrap().1 .1.join()?
        );
    }

    ushell.run(cmd!("date"))?;

    vshell.run(cmd!(
        "echo -e '{}' > {}",
        crate::common::timings_str(timers.as_slice()),
        dir!(VAGRANT_RESULTS_DIR, time_file)
    ))?;

    crate::common::exp_0sim::gen_standard_sim_output(&sim_file, &ushell, &vshell)?;

    let glob = cfg.gen_file_name("*");
    println!("RESULTS: {}", dir!(HOSTNAME_SHARED_RESULTS_DIR, glob));

    Ok(())
}