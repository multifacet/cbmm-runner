//! Run the NAS CG class E workload on the remote test machine in simulation and collect
//! compressibility stats and `/proc/vmstat` on guest during it.
//!
//! Requires `setup00000`.

use clap::clap_app;

use runner::{
    dir,
    exp_0sim::*,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    time,
    workloads::{
        run_nas_cg, run_time_mmap_touch, NasClass, TasksetCtx, TimeMmapTouchConfig,
        TimeMmapTouchPattern,
    },
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    calibrate: bool,
    warmup: bool,

    #[name]
    vm_size: usize,
    #[name]
    cores: usize,

    duration: usize,

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

    clap_app! { exp00005 =>
        (about: "Run experiment 00005. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg DURATION: +takes_value {is_usize} +required
         "The length of time to run the workload in seconds.")
        (@arg WARMUP: -w --warmup
         "Pass this flag to warmup the VM before running the main workload.")
        (@arg VMSIZE: +takes_value {is_usize}
         "The number of GBs of the VM (defaults to 2048)")
        (@arg CORES: +takes_value {is_usize} -C --cores
         "The number of cores of the VM (defaults to 1)")
    }
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let duration = sub_m
        .value_of("DURATION")
        .unwrap()
        .parse::<usize>()
        .unwrap();

    let vm_size = sub_m
        .value_of("VMSIZE")
        .map(|value| value.parse::<usize>().unwrap());
    let cores = sub_m
        .value_of("CORES")
        .map(|value| value.parse::<usize>().unwrap());
    let warmup = sub_m.is_present("WARMUP");

    let vm_size = if let Some(vm_size) = vm_size {
        vm_size
    } else {
        // NAS class E is ~2TB
        2048
    };

    let cores = if let Some(cores) = cores {
        cores
    } else {
        VAGRANT_CORES
    };

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = runner::local_research_workspace_git_hash()?;
    let remote_git_hash = runner::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = runner::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (5, "nas_cg_class_e".into()),

        calibrate: false,
        warmup,

        vm_size,
        cores,

        duration,

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
            ZEROSIM_LAPIC_ADJUST
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
    let params = serde_json::to_string(&cfg)?;

    vshell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(VAGRANT_RESULTS_DIR, params_file)
    ))?;

    let mut tctx = TasksetCtx::new(cfg.cores);

    // Warm up
    if cfg.warmup {
        const WARM_UP_PATTERN: TimeMmapTouchPattern = TimeMmapTouchPattern::Zeros;
        time!(
            timers,
            "Warmup",
            run_time_mmap_touch(
                &vshell,
                &TimeMmapTouchConfig {
                    exp_dir: zerosim_exp_path,
                    pages: (cfg.vm_size << 30) >> 12,
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

    // Record vmstat on guest
    let vmstat_file = cfg.gen_file_name("vmstat");
    let (_shell, _vmstats_handle) = vshell.spawn(
        cmd!(
            "for (( c=1 ; c<={} ; c++ )) ; do \
             cat /proc/vmstat >> {} ; sleep 1 ; done",
            cfg.duration,
            dir!(VAGRANT_RESULTS_DIR, vmstat_file)
        )
        .use_bash(),
    )?;

    // The workload takes a very long time, so we only use the first 2 hours (of wall-clock time).
    // We start this thread that collects stats in the background and terminates after the given
    // amount of time. We spawn the workload, but don't wait for it; rather, we wait for this task.
    let zswapstats_file = cfg.gen_file_name("zswapstats");
    let (_shell, zswapstats_handle) = ushell.spawn(
        cmd!(
            "for (( c=1 ; c<={} ; c++ )) ; do \
             sudo tail `sudo find  /sys/kernel/debug/zswap/ -type f`\
             >> {} ; sleep 1 ; done",
            cfg.duration,
            dir!(HOSTNAME_SHARED_RESULTS_DIR, zswapstats_file)
        )
        .use_bash(),
    )?;

    time!(timers, "Background stats collection", {
        let _ = run_nas_cg(
            &vshell,
            zerosim_bmk_path,
            NasClass::F,
            Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
            /* eager */ None,
            &mut tctx,
        )?;

        std::thread::sleep(std::time::Duration::from_secs(cfg.duration as u64));

        zswapstats_handle.join()?
    });

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
