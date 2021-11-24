//! Run the given workload on the remote machine in simulation and record its results.
//!
//! Requires `setup00000`. If `--damon` is used, then `setup00002` with the DAMON kernel is needed.

use clap::clap_app;

use crate::{
    background::{BackgroundContext, BackgroundTask},
    cli::{damon, memtrace, validator},
    dir,
    exp_0sim::*,
    get_cpu_freq,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    time,
    workloads::{
        run_graph500, run_memcached_gen_data, run_metis_matrix_mult, run_redis_gen_data,
        run_time_mmap_touch, start_redis, Damon, MemcachedWorkloadConfig, Pintool,
        RedisWorkloadConfig, TasksetCtx, TimeMmapTouchConfig, TimeMmapTouchPattern,
    },
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

pub const PERIOD: usize = 10; // seconds

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
enum Workload {
    Memcached,
    Redis,
    MatrixMult2,
    TimeMmapTouch,
    Graph500,
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    workload: Workload,

    #[name]
    vm_size: usize,
    #[name(self.scale.is_some())]
    scale: Option<usize>,
    #[name(self.cores > 1)]
    cores: usize,
    pattern: Option<TimeMmapTouchPattern>,
    prefault: bool,

    #[name(self.size.is_some())]
    size: Option<usize>,

    calibrate: bool,
    #[name(self.warmup)]
    warmup: bool,

    #[name(self.disable_zswap)]
    disable_zswap: bool,

    #[name(self.multicore_offsetting)]
    multicore_offsetting: bool,

    zswap_max_pool_percent: usize,
    #[name(self.zerosim_drift_threshold.is_some())]
    zerosim_drift_threshold: Option<usize>,
    #[name(self.zerosim_delay.is_some())]
    zerosim_delay: Option<usize>,

    #[name(self.memtrace)]
    memtrace: bool,
    #[name(self.damon)]
    damon: bool,
    #[name(self.meminfo_periodic)]
    meminfo_periodic: bool,
    damon_sample_interval: usize,
    damon_aggr_interval: usize,

    username: String,
    host: String,

    local_git_hash: String,
    remote_git_hash: String,

    remote_research_settings: std::collections::BTreeMap<String, String>,

    #[timestamp]
    timestamp: Timestamp,
}

pub fn cli_options() -> clap::App<'static, 'static> {
    let app = clap_app! { exp00000 =>
        (about: "Run experiment 00000. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg VMSIZE: +required +takes_value {validator::is::<usize>}
         "The number of GBs of the VM (e.g. 500)")
        (@arg CORES: +required +takes_value {validator::is::<usize>}
         "The number of cores of the VM")
        (@arg SCALE: +takes_value {validator::is::<usize>}
         "The scale parameter of the graph500 workload")
        (@group PATTERN =>
            (@attributes +required)
            (@arg zeros: -z "Run the time_mmap_touch workload with zeros")
            (@arg counter: -c "Run the time_mmap_touch workload with counter values")
            (@arg memcached: -m "Run a memcached workload")
            (@arg redis: -r "Run a redis workload")
            (@arg matrixmult: -M "Run the Metis matrix_mult2 workload")
            (@arg graph500: -g requires[SCALE] "Run the graph500 workload")
        )
        (@arg WARMUP: -w --warmup
         "Pass this flag to warmup the VM before running the main workload.")
        (@arg PREFAULT: -p --prefault
         "Pass this flag to prefault memory before running the main workload \
         (ignored for memcached).")
        (@arg SIZE: -s --size +takes_value {validator::is::<usize>}
         "The number of GBs of the workload (e.g. 500)")
        (@arg MULTICORE_OFFSETTING: --multicore_offsetting
         "(Optional) Enable multicore offsetting for greater accuracy at a performance cost")
        (@arg DRIFT_THRESHOLD: --drift_thresh +takes_value
         {validator::is::<usize>} requires[MULTICORE_OFFSETTING]
         "(Optional) Set multicore offsetting drift threshold.")
        (@arg DELAY: --delay +takes_value {validator::is::<usize>} requires[MULTICORE_OFFSETTING]
         "(Optional) Set multicore offsetting delay.")
        (@arg DISABLE_ZSWAP: --disable_zswap
         "(Optional; not recommended) Disable zswap, forcing the hypervisor to \
         actually swap to disk")
        (@arg MEMINFO_PERIODIC: --meminfo_periodic
         "Collect /proc/meminfo data periodically")
    };

    let app = damon::add_cli_options(app);
    let app = memtrace::add_cli_options(app);

    app
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let vm_size = sub_m.value_of("VMSIZE").unwrap().parse::<usize>().unwrap();
    let cores = sub_m.value_of("CORES").unwrap().parse::<usize>().unwrap();
    let scale = sub_m.value_of("SCALE").map(|s| s.parse::<usize>().unwrap());

    let workload = match () {
        () if sub_m.is_present("memcached") => Workload::Memcached,
        () if sub_m.is_present("redis") => Workload::Redis,
        () if sub_m.is_present("matrixmult") => Workload::MatrixMult2,
        () if sub_m.is_present("zeros") => Workload::TimeMmapTouch,
        () if sub_m.is_present("counter") => Workload::TimeMmapTouch,
        () if sub_m.is_present("graph500") => Workload::Graph500,
        _ => unreachable!(),
    };

    let pattern = if sub_m.is_present("zeros") || sub_m.is_present("counter") {
        Some(if sub_m.is_present("zeros") {
            TimeMmapTouchPattern::Zeros
        } else {
            TimeMmapTouchPattern::Counter
        })
    } else {
        None
    };

    let size = sub_m
        .value_of("SIZE")
        .map(|value| value.parse::<usize>().unwrap());
    let warmup = sub_m.is_present("WARMUP");
    let prefault = sub_m.is_present("PREFAULT");

    let zerosim_drift_threshold = sub_m
        .value_of("DRIFT_THRESHOLD")
        .map(|value| value.parse::<usize>().unwrap());
    let zerosim_delay = sub_m
        .value_of("DELAY")
        .map(|value| value.parse::<usize>().unwrap());

    let disable_zswap = sub_m.is_present("DISABLE_ZSWAP");

    let multicore_offsetting = sub_m.is_present("MULTICORE_OFFSETTING");

    let memtrace = memtrace::parse_cli_options(sub_m);
    let meminfo_periodic = sub_m.is_present("MEMINFO_PERIODIC");
    let (damon, damon_sample_interval, damon_aggr_interval) = damon::parse_cli_options(sub_m);

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = crate::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (0, "0sim_wkld".into()),

        workload,

        vm_size,
        cores,
        scale,
        pattern,
        prefault,

        size,
        calibrate: false,
        warmup,

        disable_zswap,

        multicore_offsetting,

        zswap_max_pool_percent: 50,
        zerosim_drift_threshold,
        zerosim_delay,

        memtrace,
        damon,
        meminfo_periodic,
        damon_sample_interval,
        damon_aggr_interval,

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
    if !cfg.disable_zswap {
        turn_on_ssdswap(&ushell)?;
    }

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
    if !cfg.disable_zswap {
        ZeroSim::turn_on_zswap(&mut ushell)?;
    }

    if let Some(threshold) = cfg.zerosim_drift_threshold {
        ZeroSim::threshold(&ushell, threshold)?;
    }
    if let Some(delay) = cfg.zerosim_delay {
        ZeroSim::delay(&ushell, delay)?;
    }
    ZeroSim::multicore_offsetting(&ushell, cfg.multicore_offsetting)?;
    if cfg.multicore_offsetting {
        ZeroSim::sync_guest_tsc(&ushell)?;
    }

    ZeroSim::zswap_max_pool_percent(&ushell, cfg.zswap_max_pool_percent)?;

    let zerosim_exp_path = &dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );

    let size = if let Some(size) = cfg.size {
        size // GB
    } else {
        // Get the amount of memory the guest thinks it has (in KB).
        let size = vshell
            .run(cmd!("grep MemAvailable /proc/meminfo | awk '{{print $2}}'").use_bash())?
            .stdout;
        size.trim().parse::<usize>().unwrap() >> 20 // turn into GB
    };

    // Calibrate
    if cfg.calibrate {
        time!(
            timers,
            "Calibrate",
            vshell.run(cmd!("sudo ./target/release/time_calibrate").cwd(zerosim_exp_path))?
        );
    }

    let (output_file, params_file, time_file, sim_file) = cfg.gen_standard_names();
    let params = serde_json::to_string(&cfg)?;

    let pin_path = dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_MEMBUFFER_EXTRACT_SUBMODULE,
        "pin"
    );

    // Only used for memtrace.
    let trace_path = cfg.gen_file_name("trace");
    let trace_path = dir!(VAGRANT_RESULTS_DIR, trace_path);

    // Only used for DAMON.
    let damon_output_path = cfg.gen_file_name("damon");
    let damon_output_path = dir!(VAGRANT_RESULTS_DIR, damon_output_path);

    let damon_path = dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_BENCHMARKS_DIR,
        DAMON_PATH
    );

    // Only used for meminfo_periodic.
    let meminfo_file = cfg.gen_file_name("meminfo");
    let mut bgctx = BackgroundContext::new(&vshell);
    if cfg.meminfo_periodic {
        bgctx.spawn(BackgroundTask {
            name: "meminfo",
            period: PERIOD,
            cmd: format!(
                "cat /proc/meminfo | tee -a {}",
                dir!(VAGRANT_RESULTS_DIR, &meminfo_file),
            ),
            ensure_started: dir!(VAGRANT_RESULTS_DIR, &meminfo_file),
        })?;
    }

    let runtime_file = cfg.gen_file_name("runtime");

    vshell.run(cmd!(
        "echo {} > {}",
        escape_for_bash(&params),
        dir!(VAGRANT_RESULTS_DIR, params_file)
    ))?;

    let mut tctx = TasksetCtx::new(cfg.cores);

    // Warm up
    if cfg.warmup {
        //const WARM_UP_SIZE: usize = 50; // GB
        const WARM_UP_PATTERN: TimeMmapTouchPattern = TimeMmapTouchPattern::Zeros;
        time!(
            timers,
            "Warmup",
            run_time_mmap_touch(
                &vshell,
                &TimeMmapTouchConfig {
                    exp_dir: zerosim_exp_path,
                    pages: (size << 30) >> 12,
                    pattern: WARM_UP_PATTERN,
                    prefault: false,
                    pf_time: None,
                    output_file: None,
                    pin_core: tctx.next(),
                }
            )?
        );
    }

    // We want to use rdtsc as the time source, so find the cpu freq:
    let freq = get_cpu_freq(&ushell)?;

    // Run memcached or time_touch_mmap
    match cfg.workload {
        Workload::TimeMmapTouch => {
            time!(
                timers,
                "Workload",
                run_time_mmap_touch(
                    &vshell,
                    &TimeMmapTouchConfig {
                        exp_dir: zerosim_exp_path,
                        pages: (size << 30) >> 12,
                        pattern: cfg.pattern.unwrap(),
                        prefault: cfg.prefault,
                        pf_time: None,
                        output_file: Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
                        pin_core: tctx.next(),
                    }
                )?
            );
        }

        Workload::Memcached => {
            time!(
                timers,
                "Workload",
                run_memcached_gen_data(
                    &vshell,
                    &MemcachedWorkloadConfig {
                        user: "vagrant",
                        exp_dir: zerosim_exp_path,
                        memcached: &dir!(
                            "/home/vagrant",
                            RESEARCH_WORKSPACE_PATH,
                            ZEROSIM_MEMCACHED_SUBMODULE
                        ),
                        server_size_mb: size << 10,
                        wk_size_gb: size,
                        freq: Some(freq),
                        allow_oom: true,
                        pf_time: None,
                        output_file: Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
                        client_pin_core: tctx.next(),
                        server_pin_core: None,
                        pintool: if cfg.memtrace {
                            Some(Pintool::MemTrace {
                                output_path: &trace_path,
                                pin_path: &pin_path,
                            })
                        } else {
                            None
                        },
                        damon: if cfg.damon {
                            Some(Damon {
                                output_path: &damon_output_path,
                                damon_path: &damon_path,
                                sample_interval: cfg.damon_sample_interval,
                                aggregate_interval: cfg.damon_aggr_interval,
                            })
                        } else {
                            None
                        },
                        cb_wrapper_cmd: None,
                        mmu_perf: None,
                        server_start_cb: |_| Ok(()),
                    },
                    &runtime_file
                )?
            );
        }

        Workload::Redis => {
            let nullfs_path = dir!(
                "/home/vagrant",
                RESEARCH_WORKSPACE_PATH,
                ZEROSIM_NULLFS_SUBMODULE
            );
            let out_file = dir!(VAGRANT_RESULTS_DIR, output_file);
            let cfg = RedisWorkloadConfig {
                exp_dir: zerosim_exp_path,
                server_size_mb: size << 10,
                wk_size_gb: size,
                freq: Some(freq),
                pf_time: None,
                output_file: Some(&out_file),
                client_pin_core: tctx.next(),
                server_pin_core: None,
                redis_conf: &dir!("/home/vagrant", RESEARCH_WORKSPACE_PATH, REDIS_CONF),
                nullfs: Some(nullfs_path.as_str()),
                pintool: None,
                cb_wrapper_cmd: None,
            };

            let _server_handle = time!(timers, "Start server", start_redis(&vshell, &cfg)?);

            time!(
                timers,
                "Workload",
                run_redis_gen_data(&vshell, &cfg)?.join().1?
            );
        }

        Workload::MatrixMult2 => {
            time!(
                timers,
                "Workload",
                run_metis_matrix_mult(
                    &vshell,
                    &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_METIS_SUBMODULE
                    ),
                    ((size << 27) as f64).sqrt() as usize,
                    /* cb_wrapper_cmd */ None,
                    &mut tctx,
                )?
                .join()
                .1?
            );
        }

        Workload::Graph500 => {
            time!(timers, "Workload", {
                run_graph500(
                    &vshell,
                    &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_GRAPH500_SUBMODULE
                    ),
                    cfg.scale.unwrap(),
                    &dir!(VAGRANT_RESULTS_DIR, output_file),
                    if cfg.damon {
                        Some(Damon {
                            output_path: &damon_output_path,
                            damon_path: &damon_path,
                            sample_interval: cfg.damon_sample_interval,
                            aggregate_interval: cfg.damon_aggr_interval,
                        })
                    } else {
                        None
                    },
                    if cfg.memtrace {
                        Some(Pintool::MemTrace {
                            output_path: &trace_path,
                            pin_path: &pin_path,
                        })
                    } else {
                        None
                    },
                    None,
                )?
            });
        }
    }

    time!(
        timers,
        "Waiting for meminfo thread to halt",
        bgctx.notify_and_join_all()?
    );

    // Tell damon to write data, if needed.
    if cfg.damon {
        vshell.run(cmd!(
            "echo off | sudo tee /sys/kernel/debug/damon/monitor_on"
        ))?;
    }

    ushell.run(cmd!("date"))?;

    vshell.run(cmd!(
        "echo {} > {}",
        escape_for_bash(&crate::timings_str(timers.as_slice())),
        dir!(VAGRANT_RESULTS_DIR, time_file)
    ))?;

    crate::exp_0sim::gen_standard_sim_output(&sim_file, &ushell, &vshell)?;

    let glob = cfg.gen_file_name("");
    println!("RESULTS: {}", dir!(HOSTNAME_SHARED_RESULTS_DIR, glob));

    Ok(())
}
