//! Run a workload on bare-metal (e.g. AWS).
//!
//! Requires `setup00000` with the appropriate kernel. If mmstats is passed, an instrumented kernel
//! needs to be installed. If `--damon` is used, then `setup00002` with the DAMON kernel is needed.

use clap::clap_app;

use runner::{
    background::{BackgroundContext, BackgroundTask},
    dir,
    exp_0sim::*,
    get_cpu_freq, get_user_home_dir,
    output::{Parametrize, Timestamp},
    paths::*,
    time,
    workloads::{
        run_locality_mem_access, run_memcached_gen_data, run_mix, run_time_loop,
        run_time_mmap_touch, Damon, LocalityMemAccessConfig, LocalityMemAccessMode,
        MemcachedWorkloadConfig, TasksetCtx, TimeMmapTouchConfig, TimeMmapTouchPattern,
    },
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

pub const PERIOD: usize = 10; // seconds
pub const DEFAULT_DAMON_SAMPLE_INTERVAL: usize = 5000; // msecs

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
enum Workload {
    TimeLoop {
        n: usize,
    },
    LocalityMemAccess {
        n: usize,
    },
    TimeMmapTouch {
        size: usize,
        pattern: TimeMmapTouchPattern,
    },
    Memcached {
        size: usize,
    },
    Mix {
        size: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String, String),

    workload: Workload,

    #[name(self.n > 0)]
    n: usize,
    #[name(self.size > 0)]
    size: usize,
    #[name(self.pattern.is_some())]
    pattern: Option<TimeMmapTouchPattern>,
    #[name(self.eager)]
    eager: bool,

    transparent_hugepage_enabled: String,
    transparent_hugepage_defrag: String,
    transparent_hugepage_khugepaged_defrag: usize,
    transparent_hugepage_khugepaged_alloc_sleep_ms: usize,
    transparent_hugepage_khugepaged_scan_sleep_ms: usize,

    mmstats: bool,
    meminfo_periodic: bool,
    damon: bool,
    damon_sample_interval: usize,

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

    clap_app! { exp00010 =>
        (about: "Run experiment 00010. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@subcommand time_loop =>
            (about: "Run the `time_loop` workload.")
            (@arg N: +required +takes_value {is_usize}
             "The number of iterations of the workload (e.g. 50000000), preferably \
              divisible by 8 for `locality_mem_access`")
            )
        (@subcommand locality_mem_access =>
            (about: "Run the `locality_mem_access` workload.")
            (@arg N: +required +takes_value {is_usize}
             "The number of iterations of the workload (e.g. 50000000), preferably \
              divisible by 8 for `locality_mem_access`")
        )
        (@subcommand time_mmap_touch =>
            (about: "Run the `time_mmap_touch` workload.")
            (@arg SIZE: +required +takes_value {is_usize}
             "The number of GBs of the workload (e.g. 500)")
            (@group PATTERN =>
                (@attributes +required)
                (@arg zeros: -z "Fill pages with zeros")
                (@arg counter: -c "Fill pages with counter values")
            )
        )
        (@subcommand memcached =>
            (about: "Run the `memcached` workload.")
            (@arg SIZE: +required +takes_value {is_usize}
             "The number of GBs of the workload (e.g. 500)")
        )
        (@subcommand mix =>
            (about: "Run the `mix` workload.")
            (@arg SIZE: +required +takes_value {is_usize}
             "The number of GBs of the workload (e.g. 500)")
        )
        (@arg EAGER: --eager
         "(optional) Use eager paging; requires a kernel that has eager paging.")
        (@arg MMSTATS: --memstats
         "(optional) Collect latency histograms for memory management ops; \
          requires a kernel that has instrumentation.")
        (@arg MEMINFO_PERIODIC: --meminfo_periodic
         "Collect /proc/meminfo data periodically.")
        (@arg DAMON: --damon conflicts_with[MEMTRACE]
         "Collect DAMON page access history data.")
        (@arg DAMON_SAMPLE_INT: --damon_sample_interval requires[DAMON] +takes_value {is_usize}
         "The interval with which DAMON samples access data.")
    }
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let (workload, workload_name, n, size, pattern) = match sub_m.subcommand() {
        ("time_loop", Some(sub_m)) => {
            let n = sub_m.value_of("N").unwrap().parse::<usize>().unwrap();
            (Workload::TimeLoop { n }, "time_loop", n, 0, None)
        }

        ("locality_mem_access", Some(sub_m)) => {
            let n = sub_m.value_of("N").unwrap().parse::<usize>().unwrap();
            (
                Workload::LocalityMemAccess { n },
                "locality_mem_access",
                n,
                0,
                None,
            )
        }

        ("time_mmap_touch", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();

            let pattern = if sub_m.is_present("zeros") {
                TimeMmapTouchPattern::Zeros
            } else {
                TimeMmapTouchPattern::Counter
            };

            (
                Workload::TimeMmapTouch { size, pattern },
                "time_mmap_touch",
                0,
                size,
                Some(pattern),
            )
        }

        ("memcached", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();

            (Workload::Memcached { size }, "memcached", 0, size, None)
        }

        ("mix", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();

            (Workload::Mix { size }, "mix", 0, size, None)
        }

        _ => unreachable!(),
    };

    let eager = sub_m.is_present("EAGER");
    let mmstats = sub_m.is_present("MMSTATS");
    let meminfo_periodic = sub_m.is_present("MEMINFO_PERIODIC");
    let damon = sub_m.is_present("DAMON");
    let damon_sample_interval = sub_m
        .value_of("DAMON_SAMPLE_INT")
        .map(|s| s.parse().unwrap())
        .unwrap_or(DEFAULT_DAMON_SAMPLE_INTERVAL);

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = runner::local_research_workspace_git_hash()?;
    let remote_git_hash = runner::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = runner::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (10, "bare_metal".into(), workload_name.into()),

        workload,

        n,
        size,
        pattern,
        eager,

        transparent_hugepage_enabled: "always".into(),
        transparent_hugepage_defrag: "always".into(),
        transparent_hugepage_khugepaged_defrag: 1,
        transparent_hugepage_khugepaged_alloc_sleep_ms: 1000,
        transparent_hugepage_khugepaged_scan_sleep_ms: 1000,

        mmstats,
        meminfo_periodic,
        damon,
        damon_sample_interval,

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
        user_home,
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );

    // Turn on compaction and force it too happen
    runner::turn_on_thp(
        &ushell,
        &cfg.transparent_hugepage_enabled,
        &cfg.transparent_hugepage_defrag,
        cfg.transparent_hugepage_khugepaged_defrag,
        cfg.transparent_hugepage_khugepaged_alloc_sleep_ms,
        cfg.transparent_hugepage_khugepaged_scan_sleep_ms,
    )?;

    // Collect timers on VM
    let mut timers = vec![];

    let (output_file, params_file, time_file, _sim_file) = cfg.gen_standard_names();
    let mmstats_file = cfg.gen_file_name("mmstats");
    let meminfo_file = cfg.gen_file_name("meminfo");
    let damon_output_path = cfg.gen_file_name("damon");
    let damon_output_path = dir!(
        user_home,
        setup00000::HOSTNAME_SHARED_RESULTS_DIR,
        damon_output_path
    );

    let damon_path = dir!(
        user_home,
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_BENCHMARKS_DIR,
        DAMON_PATH
    );

    let params = serde_json::to_string(&cfg)?;

    ushell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(
            user_home,
            setup00000::HOSTNAME_SHARED_RESULTS_DIR,
            params_file
        )
    ))?;

    let swapnil_path = dir!(
        user_home,
        runner::paths::RESEARCH_WORKSPACE_PATH,
        runner::paths::ZEROSIM_BENCHMARKS_DIR,
        runner::paths::ZEROSIM_SWAPNIL_PATH
    );
    let eager = if cfg.eager {
        Some(swapnil_path.as_str())
    } else {
        None
    };

    let cores = runner::get_num_cores(&ushell)?;
    let mut tctx = TasksetCtx::new(cores);

    if cfg.mmstats {
        // Print the current numbers, 'cause why not?
        ushell.run(cmd!("tail /proc/mm_*"))?;

        // Writing to any of the params will reset the plot.
        ushell.run(cmd!(
            "for h in /proc/mm_*_min ; do echo $h ; echo 0 | sudo tee $h ; done"
        ))?;
    }

    // Maybe collect meminfo
    let mut bgctx = BackgroundContext::new(&ushell);
    if cfg.meminfo_periodic {
        bgctx.spawn(BackgroundTask {
            name: "meminfo",
            period: PERIOD,
            cmd: format!(
                "cat /proc/meminfo | tee -a {}",
                dir!(
                    user_home,
                    setup00000::HOSTNAME_SHARED_RESULTS_DIR,
                    &meminfo_file
                ),
            ),
            ensure_started: dir!(
                user_home,
                setup00000::HOSTNAME_SHARED_RESULTS_DIR,
                &meminfo_file
            ),
        })?;
    }

    // Run the workload.
    match cfg.workload {
        Workload::TimeLoop { n } => {
            time!(
                timers,
                "Workload",
                run_time_loop(
                    &ushell,
                    zerosim_exp_path,
                    n,
                    &dir!(
                        user_home,
                        setup00000::HOSTNAME_SHARED_RESULTS_DIR,
                        output_file
                    ),
                    eager,
                    &mut tctx,
                )?
            );
        }

        Workload::LocalityMemAccess { n } => {
            let local_file = cfg.gen_file_name("local");
            let nonlocal_file = cfg.gen_file_name("nonlocal");

            time!(timers, "Workload", {
                run_locality_mem_access(
                    &ushell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Local,
                        n: n,
                        threads: None,
                        output_file: &dir!(
                            user_home,
                            setup00000::HOSTNAME_SHARED_RESULTS_DIR,
                            local_file
                        ),
                        eager,
                    },
                )?;
                run_locality_mem_access(
                    &ushell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Random,
                        n: n,
                        threads: None,
                        output_file: &dir!(
                            user_home,
                            setup00000::HOSTNAME_SHARED_RESULTS_DIR,
                            nonlocal_file
                        ),
                        eager,
                    },
                )?;
            });
        }

        Workload::TimeMmapTouch { size, pattern } => {
            time!(
                timers,
                "Workload",
                run_time_mmap_touch(
                    &ushell,
                    &TimeMmapTouchConfig {
                        exp_dir: zerosim_exp_path,
                        pages: (size << 30) >> 12,
                        pattern: pattern,
                        prefault: false,
                        pf_time: None,
                        output_file: Some(&dir!(
                            user_home,
                            setup00000::HOSTNAME_SHARED_RESULTS_DIR,
                            output_file
                        )),
                        eager,
                        pin_core: tctx.next(),
                    }
                )?
            );
        }

        Workload::Memcached { size } => {
            let freq = get_cpu_freq(&ushell)?;

            time!(
                timers,
                "Workload",
                run_memcached_gen_data(
                    &ushell,
                    &MemcachedWorkloadConfig {
                        user: login.username,
                        exp_dir: zerosim_exp_path,
                        memcached: &dir!(
                            user_home.as_str(),
                            RESEARCH_WORKSPACE_PATH,
                            ZEROSIM_MEMCACHED_SUBMODULE
                        ),
                        server_size_mb: size << 10,
                        wk_size_gb: size,
                        freq: Some(freq),
                        allow_oom: true,
                        pf_time: None,
                        output_file: Some(&dir!(
                            user_home.as_str(),
                            setup00000::HOSTNAME_SHARED_RESULTS_DIR,
                            output_file
                        )),
                        eager,
                        client_pin_core: tctx.next(),
                        server_pin_core: None,
                        pintool: None,
                        damon: if cfg.damon {
                            Some(Damon {
                                damon_path: &damon_path,
                                output_path: &damon_output_path,
                                sample_interval: cfg.damon_sample_interval,
                            })
                        } else {
                            None
                        },
                    }
                )?
            );
        }

        Workload::Mix { size } => {
            let freq = get_cpu_freq(&ushell)?;

            time!(timers, "Workload", {
                run_mix(
                    &ushell,
                    zerosim_exp_path,
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_METIS_SUBMODULE),
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_MEMHOG_SUBMODULE),
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_NULLFS_SUBMODULE),
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, REDIS_CONF),
                    freq,
                    size,
                    eager,
                    &mut tctx,
                )?
            });
        }
    }

    if cfg.mmstats {
        let mmstats_file = dir!(
            user_home,
            setup00000::HOSTNAME_SHARED_RESULTS_DIR,
            &mmstats_file
        );

        ushell.run(cmd!("tail /proc/mm_* | tee {}", mmstats_file))?;
        ushell.run(cmd!("cat /proc/meminfo | tee -a {}", mmstats_file))?;
        ushell.run(cmd!("cat /proc/vmstat | tee -a {}", mmstats_file))?;
    }

    if cfg.meminfo_periodic {
        time!(
            timers,
            "Waiting for data collectioned threads to halt",
            bgctx.notify_and_join_all()?
        );
    }

    // Tell damon to write data, if needed.
    if cfg.damon {
        time!(timers, "Waiting for DAMON to flush data buffers", {
            ushell.run(cmd!(
                "echo off | sudo tee /sys/kernel/debug/damon/monitor_on"
            ))?;
        })
    }

    ushell.run(cmd!("date"))?;

    ushell.run(cmd!("free -h"))?;

    ushell.run(cmd!(
        "echo -e '{}' > {}",
        runner::timings_str(timers.as_slice()),
        dir!(
            user_home,
            setup00000::HOSTNAME_SHARED_RESULTS_DIR,
            time_file
        )
    ))?;

    let glob = cfg.gen_file_name("*");
    println!(
        "RESULTS: {}",
        dir!(setup00000::HOSTNAME_SHARED_RESULTS_DIR, glob)
    );

    Ok(())
}
