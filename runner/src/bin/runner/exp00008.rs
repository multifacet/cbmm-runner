//! Run a workload in simulation and collect stats on swapping via `/proc/swap_instrumentation`.
//! The workload can be invoked either to provoke kswapd or direct reclaim.
//!
//! Requires `setup00000`. Requires `setup00001` with the `markm_instrument_swap` branch.

use clap::clap_app;

use runner::{
    dir,
    exp_0sim::*,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, setup00001::*, *},
    time,
    workloads::{
        run_memcached_gen_data, run_memhog, run_nas_cg, MemcachedWorkloadConfig, MemhogOptions,
        NasClass, TasksetCtx,
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
}

impl Workload {
    pub fn to_str(&self) -> &str {
        match self {
            Workload::Memcached => "memcached_gen_data",
            Workload::Cg => "nas_cg",
            Workload::Memhog => "memhog",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    workload: Workload,

    #[name]
    vm_size: usize,
    #[name(self.cores > 1)]
    cores: usize,

    #[name]
    factor: isize,

    stats_interval: usize,

    calibrate: bool,
    warmup: bool,

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
    fn is_isize(s: String) -> Result<(), String> {
        s.as_str()
            .parse::<isize>()
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }

    fn is_usize(s: String) -> Result<(), String> {
        s.as_str()
            .parse::<usize>()
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }

    clap_app! { exp00008 =>
        (about: "Run experiment 00008. Requires `sudo`.")
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
        )
        (@arg WARMUP: -w --warmup
         "Pass this flag to warmup the VM before running the main workload.")
        (@arg VMSIZE: +takes_value {is_usize} --vm_size
         "The number of GBs of the VM (defaults to 2048)")
        (@arg CORES: +takes_value {is_usize} -C --cores
         "The number of cores of the VM (defaults to 1)")
        (@arg FACTOR: +takes_value {is_isize} -f --factor
         "The reclaim order extra factor (defaults to 0). Can be positive or negative, \
         but the absolute value should be less than MAX_ORDER for the guest kernel.")
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

    let workload = if sub_m.is_present("memcached") {
        Workload::Memcached
    } else if sub_m.is_present("cg") {
        Workload::Cg
    } else if sub_m.is_present("memhog") {
        Workload::Memhog
    } else {
        panic!("unknown workload")
    };

    let vm_size = if let Some(vm_size) = sub_m
        .value_of("VMSIZE")
        .map(|value| value.parse::<usize>().unwrap())
    {
        vm_size
    } else {
        // NAS class E is ~2TB
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

    let factor = if let Some(factor) = sub_m
        .value_of("FACTOR")
        .map(|value| value.parse::<isize>().unwrap())
    {
        factor
    } else {
        0
    };

    let warmup = sub_m.is_present("WARMUP");

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = runner::local_research_workspace_git_hash()?;
    let remote_git_hash = runner::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = runner::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (8, format!("swap_{}", workload.to_str())),

        workload,

        calibrate: false,
        warmup,

        vm_size,
        cores,

        factor,

        stats_interval: interval,

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

    // Mount the guest swap file
    vshell.run(cmd!("sudo swapon {}", VAGRANT_GUEST_SWAPFILE))?;

    // Get the amount of memory the guest thinks it has. (KB)
    let mem_avail = {
        let mem_avail = vshell
            .run(cmd!("grep MemAvailable /proc/meminfo | awk '{{print $2}}'").use_bash())?
            .stdout;
        mem_avail.trim().parse::<usize>().unwrap()
    };
    let swap_avail = {
        let swap_avail = vshell
            .run(cmd!("grep SwapFree /proc/meminfo | awk '{{print $2}}'").use_bash())?
            .stdout;
        swap_avail.trim().parse::<usize>().unwrap()
    };

    // Compute a workload size that is large enough to cause reclamation but small enough to not
    // trigger OOM killer.
    let size = mem_avail + (8 * swap_avail / 10); // KB

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

    if cfg.factor != 0 {
        vshell.run(cmd!(
            "echo {} | sudo tee /proc/swap_extra_factor",
            cfg.factor
        ))?;
    }

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

    // Record swap_instrumentation on the guest until signalled to stop.
    let vshell2 = connect_to_vagrant_as_root(login.hostname)?;
    let (_shell, buddyinfo_handle) = vshell2.spawn(
        cmd!(
            "rm -f /tmp/exp-stop ; \
             while [ ! -e /tmp/exp-stop ] ; do \
             cat /proc/swap_instrumentation | tee -a {} ; \
             sleep {} ; \
             done ; \
             cat /proc/swap_instrumentation | tee -a {} ; \
             echo done measuring",
            dir!(VAGRANT_RESULTS_DIR, output_file.as_str()),
            cfg.stats_interval,
            dir!(VAGRANT_RESULTS_DIR, output_file.as_str()),
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

    let freq = runner::get_cpu_freq(&ushell)?;
    let mut tctx = TasksetCtx::new(cfg.cores);

    // Start the hog process and give it all memory... the hope is that this gets oom killed
    // eventually, but not before some reclaim happens.
    vshell.run(cmd!("rm -f /tmp/hog_ready"))?;

    vshell.run(cmd!(
        "(nohup {}/target/release/hog {} &) ; ps",
        dir!(
            "/home/vagrant",
            RESEARCH_WORKSPACE_PATH,
            ZEROSIM_EXPERIMENTS_SUBMODULE
        ),
        size / 4 // pages
    ))?;

    vshell.run(cmd!("ps aux | grep hog"))?;

    // Wait to make sure the hog has started
    vshell.run(cmd!("while [ ! -e /tmp/hog_ready ] ; do sleep 1 ; done",).use_bash())?;

    // Run the actual workload
    match cfg.workload {
        Workload::Memcached => {
            // Start workload
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
                        allow_oom: false,
                        pf_time: None,
                        output_file: None,
                        eager: None,
                        client_pin_core: tctx.next(),
                        server_pin_core: None,
                        pintool: None,
                    }
                )?
            );
        }

        Workload::Cg => {
            time!(timers, "Workload", {
                let _ = run_nas_cg(
                    &vshell,
                    zerosim_bmk_path,
                    NasClass::F,
                    Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
                    /* eager */ None,
                    &mut tctx,
                )?;

                std::thread::sleep(std::time::Duration::from_secs(3600 * NAS_CG_HOURS));
            });
        }

        Workload::Memhog => {
            time!(
                timers,
                "Workload",
                run_memhog(
                    &vshell,
                    &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_MEMHOG_SUBMODULE
                    ),
                    Some(MEMHOG_R),
                    size,
                    MemhogOptions::empty(),
                    /* eager */ None,
                    &mut tctx,
                )?
            );
        }
    }

    vshell.run(cmd!("touch /tmp/exp-stop"))?;
    time!(
        timers,
        "Waiting for swap_instrumentation thread to halt",
        buddyinfo_handle.join()?
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
