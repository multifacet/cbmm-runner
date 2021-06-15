//! Run a workload in simulation and collect stats on fragmentation via `/proc/buddyinfo`. The
//! workload is made to consume all of the guest memory (which is less than the amount given to
//! QEMU/KVM because of VM overhead).
//!
//! Requires `setup00000`. If `--mmstats` is used, then `setup00002` with an instrumented kernel is
//! needed.

use clap::clap_app;

use crate::{
    background::{BackgroundContext, BackgroundTask},
    cli::validator,
    dir,
    exp_0sim::*,
    get_cpu_freq,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    time,
    workloads::{
        run_memcached_gen_data, run_memhog, run_metis_matrix_mult, run_mix, run_redis_gen_data,
        spawn_nas_cg, MemcachedWorkloadConfig, MemhogOptions, NasClass, RedisWorkloadConfig,
        TasksetCtx,
    },
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

/// The amount of time (in hours) to let the NAS CG workload run.
const NAS_CG_HOURS: u64 = 6;

/// The number of iterations for `memhog`.
const MEMHOG_R: usize = 10;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
enum Workload {
    Memcached,
    Cg,
    Memhog,
    Mix,
    Redis,
    MatrixMult2,
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    workload: Workload,

    calibrate: bool,
    #[name(self.warmup)]
    warmup: bool,

    #[name(self.eager)]
    eager: bool,

    #[name]
    vm_size: usize,
    #[name]
    cores: usize,

    stats_interval: usize,
    mmstats: bool,
    mmstats_periodic: bool,

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
    clap_app! { exp00007 =>
        (about: "Run experiment 00007. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg INTERVAL: +required +takes_value {validator::is::<usize>}
         "The interval at which to collect stats (seconds)")
        (@group WORKLOAD =>
            (@attributes +required)
            (@arg memcached: -m "Run the memcached workload")
            (@arg cg: -c "Run the NAS Parallel Benchmark CG workload")
            (@arg memhog: -h "Run the memhog workload")
            (@arg redis: -r "Run the redis workload")
            (@arg matrix: -M "Run the matrix multiplication workload")
            (@arg mix: -x "Run the mix workload")
        )
        (@arg WARMUP: -w --warmup
         "Pass this flag to warmup the VM before running the main workload.")
        (@arg VMSIZE: +takes_value {validator::is::<usize>} --vm_size
         "The number of GBs of the VM (defaults to 2048)")
        (@arg CORES: +takes_value {validator::is::<usize>} -C --cores
         "The number of cores of the VM (defaults to 1)")
        (@arg EAGER_PAGING: --eager
         "Run the workload with eager paging")
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
    let interval = sub_m
        .value_of("INTERVAL")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mmstats = sub_m.is_present("MMSTATS");
    let periodic = sub_m.is_present("PERIODIC");

    let workload = match () {
        () if sub_m.is_present("memcached") => Workload::Memcached,
        () if sub_m.is_present("cg") => Workload::Cg,
        () if sub_m.is_present("memhog") => Workload::Memhog,
        () if sub_m.is_present("mix") => Workload::Mix,
        () if sub_m.is_present("redis") => Workload::Redis,
        () if sub_m.is_present("matrix") => Workload::MatrixMult2,
        () => unreachable!(),
    };

    let vm_size = if let Some(vm_size) = sub_m
        .value_of("VMSIZE")
        .map(|value| value.parse::<usize>().unwrap())
    {
        vm_size
    } else {
        // NAS class F is ~2TB
        2048
    };

    let cores = if let Some(cores) = sub_m
        .value_of("CORES")
        .map(|value| value.parse::<usize>().unwrap())
    {
        cores
    } else {
        VAGRANT_CORES
    };

    let warmup = sub_m.is_present("WARMUP");

    let eager = sub_m.is_present("EAGER_PAGING");

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = crate::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (7, "fragmentation".into()),

        workload,

        calibrate: false,
        warmup,

        eager,

        vm_size,
        cores,

        stats_interval: interval,
        mmstats,
        mmstats_periodic: periodic,

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

    // Environment
    ZeroSim::turn_on_zswap(&mut ushell)?;

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
            ZEROSIM_LAPIC_ADJUST
        )?
    );

    // Get the amount of memory the guest thinks it has (in KB).
    let size = vshell
        .run(cmd!("grep MemAvailable /proc/meminfo | awk '{{print $2}}'").use_bash())?
        .stdout;
    let size = size.trim().parse::<usize>().unwrap();

    ZeroSim::zswap_max_pool_percent(&ushell, cfg.zswap_max_pool_percent)?;

    let zerosim_exp_path = &dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );
    let zerosim_bmk_path = &dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_BENCHMARKS_DIR
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
    let guest_mem_file = cfg.gen_file_name("guest_mem");
    let params = serde_json::to_string(&cfg)?;

    let runtime_file = cfg.gen_file_name("runtime");

    vshell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(VAGRANT_RESULTS_DIR, params_file)
    ))?;

    vshell.run(cmd!(
        "cat /proc/meminfo > {}",
        dir!(VAGRANT_RESULTS_DIR, guest_mem_file)
    ))?;

    // Warm up
    if cfg.warmup {
        const WARM_UP_PATTERN: &str = "-z";
        time!(
            timers,
            "Warmup",
            vshell.run(
                cmd!(
                    "sudo ./target/release/time_mmap_touch {} {} > /dev/null",
                    size >> 12,
                    WARM_UP_PATTERN,
                )
                .cwd(zerosim_exp_path)
                .use_bash(),
            )?
        );
    }

    let swapnil_path = dir!(
        "/home/vagrant/",
        crate::paths::RESEARCH_WORKSPACE_PATH,
        crate::paths::ZEROSIM_BENCHMARKS_DIR,
        crate::paths::ZEROSIM_SWAPNIL_PATH
    );
    let eager = if cfg.eager {
        Some(swapnil_path.as_str())
    } else {
        None
    };

    // We want to use rdtsc as the time source, so find the cpu freq:
    let freq = get_cpu_freq(&ushell)?;

    let mut tctx = TasksetCtx::new(cfg.cores);

    // Record buddyinfo on the guest until signalled to stop.
    let mut bgctx = BackgroundContext::new(&vshell);
    bgctx.spawn(BackgroundTask {
        name: "buddyinfo",
        period: cfg.stats_interval,
        cmd: format!(
            "cat /proc/buddyinfo | tee -a {}",
            dir!(VAGRANT_RESULTS_DIR, output_file.as_str()),
        ),
        ensure_started: dir!(VAGRANT_RESULTS_DIR, output_file.as_str()),
    })?;

    // Collect mm stats
    let mmstats_file = cfg.gen_file_name("mmstats");

    // Set histogram parameters before workload.
    if cfg.mmstats && !cfg.mmstats_periodic {
        // Print the current numbers, 'cause why not?
        vshell.run(cmd!("tail /proc/mm_*"))?;

        // Writing to any of the params will reset the plot.
        vshell.run(cmd!(
            "for h in /proc/mm_*_min ; do echo $h ; echo 0 | sudo tee $h ; done"
        ))?;
    }

    if cfg.mmstats_periodic {
        // Read and reset stats over PERIOD seconds.
        bgctx.spawn(BackgroundTask {
            name: "histograms",
            period: cfg.stats_interval,
            cmd: format!(
                "tail /proc/mm_* | tee -a {} ; \
                 for h in /proc/mm_*_min ; do echo $h ; echo 0 | sudo tee $h ; done",
                dir!(VAGRANT_RESULTS_DIR, &mmstats_file),
            ),
            ensure_started: dir!(VAGRANT_RESULTS_DIR, &mmstats_file),
        })?;
    }

    // Run the actual workload
    match cfg.workload {
        Workload::Memcached => {
            time!(
                timers,
                "Start and Workload",
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
                        server_size_mb: size >> 10,
                        wk_size_gb: size >> 20,
                        freq: Some(freq),
                        allow_oom: true,
                        pf_time: None,
                        output_file: None,
                        eager,
                        client_pin_core: tctx.next(),
                        server_pin_core: None,
                        pintool: None,
                        damon: None,
                        cb_wrapper_cmd: None,
                        mmu_perf: None,
                        server_start_cb: |_| Ok(()),
                    },
                    &runtime_file
                )?
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
                    ((size << 7) as f64).sqrt() as usize,
                    eager,
                    /* cb_wrapper_cmd */ None,
                    &mut tctx,
                )?
                .join()
                .1?
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
                        server_size_mb: size >> 10,
                        wk_size_gb: size >> 20,
                        freq: Some(freq),
                        pf_time: None,
                        output_file: None,
                        eager,
                        client_pin_core: tctx.next(),
                        server_pin_core: None,
                        redis_conf: &dir!("/home/vagrant", RESEARCH_WORKSPACE_PATH, REDIS_CONF),
                        nullfs: &dir!(
                            "/home/vagrant",
                            RESEARCH_WORKSPACE_PATH,
                            ZEROSIM_NULLFS_SUBMODULE
                        ),
                        pintool: None,
                        cb_wrapper_cmd: None,
                    }
                )?
                .wait_for_client()?
            );
        }

        Workload::Cg => {
            time!(timers, "Workload", {
                let _ = spawn_nas_cg(
                    &vshell,
                    zerosim_bmk_path,
                    NasClass::F,
                    Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
                    None,
                    None,
                    eager,
                    &mut tctx,
                )?;

                std::thread::sleep(std::time::Duration::from_secs(3600 * NAS_CG_HOURS));
            });
        }

        Workload::Memhog => {
            time!(timers, "Workload", {
                run_memhog(
                    &vshell,
                    &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_MEMHOG_SUBMODULE
                    ),
                    Some(MEMHOG_R),
                    size,
                    MemhogOptions::PIN | MemhogOptions::DATA_OBLIV,
                    eager,
                    /* cb_wrapper_cmd */ None,
                    &mut tctx,
                )?
                .join()
                .1?
            });
        }

        Workload::Mix => {
            time!(timers, "Workload", {
                run_mix(
                    &vshell,
                    zerosim_exp_path,
                    &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_METIS_SUBMODULE
                    ),
                    &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_MEMHOG_SUBMODULE
                    ),
                    &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_NULLFS_SUBMODULE
                    ),
                    &dir!("/home/vagrant", RESEARCH_WORKSPACE_PATH, REDIS_CONF,),
                    /* cb_wrapper_cmd */ None,
                    freq,
                    size >> 20,
                    eager,
                    &mut tctx,
                    &runtime_file,
                )?
            });
        }
    }

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
    }

    time!(
        timers,
        "Waiting for data collection threads to halt",
        bgctx.notify_and_join_all()?
    );

    ushell.run(cmd!("date"))?;

    vshell.run(cmd!(
        "echo -e '{}' > {}",
        crate::timings_str(timers.as_slice()),
        dir!(VAGRANT_RESULTS_DIR, time_file)
    ))?;

    crate::exp_0sim::gen_standard_sim_output(&sim_file, &ushell, &vshell)?;

    let glob = cfg.gen_file_name("");
    println!("RESULTS: {}", dir!(HOSTNAME_SHARED_RESULTS_DIR, glob));

    Ok(())
}
