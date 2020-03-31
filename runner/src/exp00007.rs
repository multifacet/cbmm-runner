//! Run a workload in simulation and collect stats on fragmentation via `/proc/buddyinfo`. The
//! workload is made to consume all of the guest memory (which is less than the amount given to
//! QEMU/KVM because of VM overhead).
//!
//! Requires `setup00000`.

use clap::clap_app;

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

use crate::common::{
    exp_0sim::*,
    get_cpu_freq,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    workloads::{
        run_memcached_gen_data, run_memhog, run_metis_matrix_mult, run_mix, run_nas_cg,
        run_redis_gen_data, MemcachedWorkloadConfig, MemhogOptions, NasClass, RedisWorkloadConfig,
        TasksetCtx,
    },
};

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
    workload: String,
    #[name]
    app: Workload,
    exp: usize,

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

    clap_app! { exp00007 =>
        (about: "Run experiment 00007. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg INTERVAL: +required +takes_value {is_usize}
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
        (@arg VMSIZE: +takes_value {is_usize} --vm_size
         "The number of GBs of the VM (defaults to 2048)")
        (@arg CORES: +takes_value {is_usize} -C --cores
         "The number of cores of the VM (defaults to 1)")
        (@arg EAGER_PAGING: --eager
         "Run the workload with eager paging")
    }
}

pub fn run(print_results_path: bool, sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
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
    let local_git_hash = crate::common::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::common::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::common::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        workload: "fragmentation".into(),
        app: workload,
        exp: 7,

        calibrate: false,
        warmup,

        eager,

        vm_size,
        cores,

        stats_interval: interval,

        zswap_max_pool_percent: 50,

        username: login.username.into(),
        host: login.hostname.into(),

        local_git_hash,
        remote_git_hash,

        remote_research_settings,

        timestamp: Timestamp::now(),
    };

    run_inner(print_results_path, &login, &cfg)
}

fn run_inner<A>(
    print_results_path: bool,
    login: &Login<A>,
    cfg: &Config,
) -> Result<(), failure::Error>
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

    // We want to use rdtsc as the time source, so find the cpu freq:
    let freq = get_cpu_freq(&ushell)?;

    let mut tctx = TasksetCtx::new(cfg.cores);

    // Record buddyinfo on the guest until signalled to stop.
    vshell.run(cmd!("rm -f /tmp/exp-stop"))?;

    let vshell2 = connect_to_vagrant_as_root(login.hostname)?;
    let (_shell, buddyinfo_handle) = vshell2.spawn(
        cmd!(
            "while [ ! -e /tmp/exp-stop ] ; do \
             cat /proc/buddyinfo | tee -a {} ; \
             sleep {} ; \
             done ; echo done measuring",
            dir!(VAGRANT_RESULTS_DIR, output_file.as_str()),
            cfg.stats_interval
        )
        .use_bash(),
    )?;

    // Wait to make sure the collection of stats has started
    vshell.run(
        cmd!(
            "while [ ! -e {} ] ; do sleep 1 ; done",
            dir!(VAGRANT_RESULTS_DIR, output_file.as_str()),
        )
        .use_bash(),
    )?;

    // Run the actual workload
    match cfg.app {
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
                        eager: cfg.eager,
                        client_pin_core: tctx.next(),
                        server_pin_core: None,
                        pintool: None,
                    }
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
                    cfg.eager,
                    &mut tctx,
                )?
                .1
                .join()?
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
                        eager: cfg.eager,
                        client_pin_core: tctx.next(),
                        server_pin_core: None,
                        redis_conf: &dir!("/home/vagrant", RESEARCH_WORKSPACE_PATH, REDIS_CONF),
                        nullfs: &dir!(
                            "/home/vagrant",
                            RESEARCH_WORKSPACE_PATH,
                            ZEROSIM_NULLFS_SUBMODULE
                        )
                    }
                )?
                .wait_for_client()?
            );
        }

        Workload::Cg => {
            time!(timers, "Workload", {
                let _ = run_nas_cg(
                    &vshell,
                    zerosim_bmk_path,
                    NasClass::F,
                    Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
                    cfg.eager,
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
                    cfg.eager,
                    &mut tctx,
                )?
                .1
                .join()?
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
                    freq,
                    size >> 20,
                    cfg.eager,
                    &mut tctx,
                )?
            });
        }
    }

    vshell.run(cmd!("touch /tmp/exp-stop"))?;
    time!(
        timers,
        "Waiting for buddyinfo thread to halt",
        buddyinfo_handle.join()?
    );

    ushell.run(cmd!("date"))?;

    vshell.run(cmd!(
        "echo -e '{}' > {}",
        crate::common::timings_str(timers.as_slice()),
        dir!(VAGRANT_RESULTS_DIR, time_file)
    ))?;

    crate::common::exp_0sim::gen_standard_sim_output(&sim_file, &ushell, &vshell)?;

    if print_results_path {
        let glob = cfg.gen_file_name("*");
        println!("RESULTS: {}", dir!(HOSTNAME_SHARED_RESULTS_DIR, glob));
    }

    Ok(())
}
