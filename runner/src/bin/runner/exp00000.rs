//! Run the given workload on the remote machine in simulation and record its results.
//!
//! Requires `setup00000`. If `--damon` is used, then `setup00002` with the DAMON kernel is needed.

use clap::clap_app;

use runner::{
    dir,
    exp_0sim::*,
    get_cpu_freq,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    time,
    workloads::{
        run_memcached_gen_data, run_metis_matrix_mult, run_redis_gen_data, run_time_mmap_touch,
        Damon, MemcachedWorkloadConfig, Pintool, RedisWorkloadConfig, TasksetCtx,
        TimeMmapTouchConfig, TimeMmapTouchPattern,
    },
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
enum Workload {
    Memcached,
    Redis,
    MatrixMult2,
    TimeMmapTouch,
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    workload: Workload,

    #[name]
    vm_size: usize,
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

    clap_app! { exp00000 =>
        (about: "Run experiment 00000. Requires `sudo`.")
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
        (@group PATTERN =>
            (@attributes +required)
            (@arg zeros: -z "Run the time_mmap_touch workload with zeros")
            (@arg counter: -c "Run the time_mmap_touch workload with counter values")
            (@arg memcached: -m "Run a memcached workload")
            (@arg redis: -r "Run a redis workload")
            (@arg matrixmult: -M "Run the Metis matrix_mult2 workload")
        )
        (@arg WARMUP: -w --warmup
         "Pass this flag to warmup the VM before running the main workload.")
        (@arg PREFAULT: -p --prefault
         "Pass this flag to prefault memory before running the main workload \
         (ignored for memcached).")
        (@arg SIZE: -s --size +takes_value {is_usize}
         "The number of GBs of the workload (e.g. 500)")
        (@arg MULTICORE_OFFSETTING: --multicore_offsetting
         "(Optional) Enable multicore offsetting for greater accuracy at a performance cost")
        (@arg DRIFT_THRESHOLD: --drift_thresh +takes_value {is_usize} requires[MULTICORE_OFFSETTING]
         "(Optional) Set multicore offsetting drift threshold.")
        (@arg DELAY: --delay +takes_value {is_usize} requires[MULTICORE_OFFSETTING]
         "(Optional) Set multicore offsetting delay.")
        (@arg DISABLE_ZSWAP: --disable_zswap
         "(Optional; not recommended) Disable zswap, forcing the hypervisor to \
         actually swap to disk")
        (@arg MEMTRACE: --memtrace conflicts_with[DAMON]
         "(Optional) collect a memory access trace of the workload. This could be multiple \
         gigabytes in size.")
        (@arg DAMON: --damon conflicts_with[MEMTRACE]
         "Collect DAMON page access history data")
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

    let workload = if sub_m.is_present("memcached") {
        Workload::Memcached
    } else if sub_m.is_present("redis") {
        Workload::Redis
    } else if sub_m.is_present("matrixmult") {
        Workload::MatrixMult2
    } else if sub_m.is_present("zeros") {
        Workload::TimeMmapTouch
    } else if sub_m.is_present("counter") {
        Workload::TimeMmapTouch
    } else {
        unreachable!();
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

    let memtrace = sub_m.is_present("MEMTRACE");
    let damon = sub_m.is_present("DAMON");

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = runner::local_research_workspace_git_hash()?;
    let remote_git_hash = runner::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = runner::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (0, "0sim_wkld".into()),

        workload,

        vm_size,
        cores,
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

    vshell.run(cmd!(
        "echo '{}' > {}",
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
                    eager: None,
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
                        eager: None,
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
                        eager: None,
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
                            })
                        } else {
                            None
                        }
                    }
                )?
            );
        }

        Workload::Redis => {
            time!(
                timers,
                "Start and Workload",
                run_redis_gen_data(
                    &vshell,
                    &RedisWorkloadConfig {
                        exp_dir: zerosim_exp_path,
                        server_size_mb: size << 10,
                        wk_size_gb: size,
                        freq: Some(freq),
                        pf_time: None,
                        output_file: Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
                        eager: None,
                        client_pin_core: tctx.next(),
                        server_pin_core: None,
                        redis_conf: &dir!("/home/vagrant", RESEARCH_WORKSPACE_PATH, REDIS_CONF),
                        nullfs: &dir!(
                            "/home/vagrant",
                            RESEARCH_WORKSPACE_PATH,
                            ZEROSIM_NULLFS_SUBMODULE
                        ),
                        pintool: None,
                    }
                )?
                .wait_for_client()?
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
                    /* eager */ None,
                    &mut tctx,
                )?
                .join()
                .1?
            );
        }
    }

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
