//! Run the `time_loop` or `locality_mem_access` workload on the remote test machine.
//!
//! Requires `setup00000`.

use clap::clap_app;

use crate::{
    cli::validator,
    dir,
    exp_0sim::*,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    time,
    workloads::{
        run_locality_mem_access, run_time_loop, run_time_mmap_touch, LocalityMemAccessConfig,
        LocalityMemAccessMode, TasksetCtx, TimeMmapTouchConfig, TimeMmapTouchPattern,
    },
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

/// Which workload to run?
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
enum Workload {
    /// `time_loop`
    TimeLoop,

    /// Single-threaded `locality_mem_access`
    LocalityMemAccess,

    /// Multithreaded `locality_mem_access` with the given number of threads
    MtLocalityMemAccess(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    workload: Workload,

    warmup: bool,
    calibrate: bool,
    #[name]
    n: usize,
    #[name(self.threads > 1)]
    threads: usize,

    #[name]
    vm_size: usize,
    cores: usize,

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
    clap_app! { exp00002 =>
        (about: "Run experiment 00002. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg N: +required +takes_value {validator::is::<usize>}
         "The number of iterations of the workload (e.g. 50000000), preferably \
          divisible by 8 for `locality_mem_access`")
        (@arg VMSIZE: +takes_value {validator::is::<usize>} -v --vm_size
         "The number of GBs of the VM (defaults to 1024)")
        (@arg CORES: +takes_value {validator::is::<usize>} -C --cores
         "The number of cores of the VM (defaults to 1)")
        (@arg WARMUP: -w --warmup
         "Pass this flag to warmup the VM before running the main workload.")
        (@group WORKLOAD =>
            (@attributes +required)
            (@arg TIME_LOOP: -t "Run time_loop")
            (@arg LOCALITY: -l "Run locality_mem_access")
            (@arg MTLOCALITY: -L +takes_value {validator::is::<usize>}
             "Run multithreaded locality_mem_access with the given number of threads")
        )
    }
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };
    let n = sub_m.value_of("N").unwrap().parse::<usize>().unwrap();
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
        VAGRANT_MEM
    };

    let cores = if let Some(cores) = cores {
        cores
    } else {
        VAGRANT_CORES
    };

    let mut nthreads = 1;

    let workload = if sub_m.is_present("TIME_LOOP") {
        Workload::TimeLoop
    } else if sub_m.is_present("LOCALITY") {
        Workload::LocalityMemAccess
    } else if let Some(threads) = sub_m.value_of("MTLOCALITY") {
        let threads = threads.parse().unwrap();
        nthreads = threads;
        Workload::MtLocalityMemAccess(threads)
    } else {
        unreachable!()
    };

    let ushell = SshShell::with_default_key(&login.username, &login.host)?;
    let local_git_hash = crate::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (2, "mem_ubench".into()),

        workload,

        warmup,
        calibrate: false,
        n,
        threads: nthreads,

        vm_size,
        cores,

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
                    pages: ((cfg.vm_size << 30) >> 12) >> 1,
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

    // Then, run the actual experiment
    match cfg.workload {
        Workload::TimeLoop => {
            time!(
                timers,
                "Workload",
                run_time_loop(
                    &vshell,
                    zerosim_exp_path,
                    cfg.n,
                    &dir!(VAGRANT_RESULTS_DIR, output_file),
                    /* eager */ None,
                    &mut tctx,
                )?
            );
        }

        Workload::LocalityMemAccess => {
            let local_file = cfg.gen_file_name("local");
            let nonlocal_file = cfg.gen_file_name("nonlocal");

            time!(timers, "Workload", {
                run_locality_mem_access(
                    &vshell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Local,
                        n: cfg.n,
                        threads: None,
                        output_file: &dir!(VAGRANT_RESULTS_DIR, local_file),
                        eager: None,
                    },
                )?;
                run_locality_mem_access(
                    &vshell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Random,
                        n: cfg.n,
                        threads: None,
                        output_file: &dir!(VAGRANT_RESULTS_DIR, nonlocal_file),
                        eager: None,
                    },
                )?;
            });
        }

        Workload::MtLocalityMemAccess(threads) => {
            let local_file = cfg.gen_file_name("local");
            let nonlocal_file = cfg.gen_file_name("nonlocal");

            time!(timers, "Workload", {
                run_locality_mem_access(
                    &vshell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Local,
                        n: cfg.n,
                        threads: Some(threads),
                        output_file: &dir!(VAGRANT_RESULTS_DIR, local_file),
                        eager: None,
                    },
                )?;
                run_locality_mem_access(
                    &vshell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Random,
                        n: cfg.n,
                        threads: Some(threads),
                        output_file: &dir!(VAGRANT_RESULTS_DIR, nonlocal_file),
                        eager: None,
                    },
                )?;
            });
        }
    }

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
