//! This file is for temporary experiments. If an experiment has long-term value, it should be
//! moved to another file and given an actual experiment number.
//!
//! Requires `setup00000`.

use clap::{clap_app, ArgMatches};

use crate::{
    cli::validator,
    dir,
    exp_0sim::*,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    time,
    workloads::{
        run_locality_mem_access, run_memcached_gen_data, run_time_mmap_touch,
        LocalityMemAccessConfig, LocalityMemAccessMode, MemcachedWorkloadConfig, TasksetCtx,
        TimeMmapTouchConfig, TimeMmapTouchPattern,
    },
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

/// # of iterations for locality_mem_access workload
const LOCALITY_N: usize = 10_000;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
enum Workload {
    Memcached,
    Zeros,
    Counter,
    Locality,
    HiBenchWordcount,
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: String,

    #[name]
    workload: Workload,

    #[name]
    size: usize,
    pattern: Option<TimeMmapTouchPattern>,
    calibrate: bool,
    warmup: bool,
    pf_time: Option<u64>,

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
    clap_app! { exptmp =>
        (about: "Run the temporary experiment.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg SIZE: +required +takes_value {validator::is::<usize>}
         "The number of GBs of the workload (e.g. 500)")
        (@group PATTERN =>
            (@attributes +required)
            (@arg zeros: -z "Fill pages with zeros")
            (@arg counter: -c "Fill pages with counter values")
            (@arg memcached: -m "Run a memcached workload")
            (@arg locality: -l "Run the locality test workload")
            (@arg hibench_wordcount: -b "Run HiBench Wordcount")
        )
        (@arg VMSIZE: +takes_value {validator::is::<usize>} -v --vm_size
         "The number of GBs of the VM (defaults to 1024) (e.g. 500)")
        (@arg CORES: +takes_value {validator::is::<usize>} -C --cores
         "The number of cores of the VM (defaults to 1)")
        (@arg WARMUP: -w --warmup
         "Pass this flag to warmup the VM before running the main workload.")
        (@arg PFTIME: +takes_value {validator::is::<usize>} --pftime
         "Pass this flag to set the pf_time value for the workload.")
    }
}

pub fn run(sub_m: &ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };
    let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();
    let workload = if sub_m.is_present("memcached") {
        Workload::Memcached
    } else if sub_m.is_present("zeros") {
        Workload::Zeros
    } else if sub_m.is_present("counter") {
        Workload::Counter
    } else if sub_m.is_present("locality") {
        Workload::Locality
    } else if sub_m.is_present("hibench_wordcount") {
        Workload::HiBenchWordcount
    } else {
        panic!("unknown workload")
    };
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

    let pf_time = sub_m
        .value_of("PFTIME")
        .map(|s| s.to_string().parse::<u64>().unwrap());

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = crate::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        workload,
        exp: "tmp".into(),

        size,
        pattern: match workload {
            Workload::Memcached | Workload::Locality | Workload::HiBenchWordcount => None,
            Workload::Zeros => Some(TimeMmapTouchPattern::Zeros),
            Workload::Counter => Some(TimeMmapTouchPattern::Counter),
        },
        calibrate: false,
        warmup,
        pf_time,

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

    let zerosim_path = &dir!("/home/vagrant", RESEARCH_WORKSPACE_PATH,);
    let zerosim_exp_path = &dir!(zerosim_path, ZEROSIM_EXPERIMENTS_SUBMODULE);

    // let zerosim_path_host = &dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_KERNEL_SUBMODULE);

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

    let runtime_file = cfg.gen_file_name("runtime");

    let mut tctx = TasksetCtx::new(cfg.cores);

    // Warm up
    //const WARM_UP_SIZE: usize = 50; // GB
    if cfg.warmup {
        const WARM_UP_PATTERN: TimeMmapTouchPattern = TimeMmapTouchPattern::Zeros;
        time!(
            timers,
            "Warmup",
            run_time_mmap_touch(
                &vshell,
                &TimeMmapTouchConfig {
                    exp_dir: zerosim_exp_path,
                    pages: (cfg.size << 30) >> 12,
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
    let freq = crate::get_cpu_freq(&ushell)?;

    // Run the workload
    match cfg.workload {
        Workload::Zeros | Workload::Counter => {
            let pattern = cfg.pattern.unwrap();

            // const PERF_MEASURE_TIME: usize = 960; // seconds
            // let perf_output_early = settings.gen_file_name("perfdata0");
            // let spawn_handle0 = ushell.spawn(cmd!(
            //     "sudo taskset -c 3 {}/tools/perf/perf stat -C 0 -I 1000 \
            //      -e 'cycles,cache-misses,dTLB-load-misses,dTLB-store-misses,\
            //      page-faults,context-switches,vmscan:*,kvm:*' -o {} sleep {}",
            //     zerosim_path_host,
            //     dir!(HOSTNAME_SHARED_RESULTS_DIR,
            //     perf_output_early),
            //     PERF_MEASURE_TIME,
            // ))?;

            // Then, run the actual experiment
            time!(
                timers,
                "Workload",
                run_time_mmap_touch(
                    &vshell,
                    &TimeMmapTouchConfig {
                        exp_dir: zerosim_exp_path,
                        pages: (cfg.size << 30) >> 12,
                        pattern: pattern,
                        prefault: false,
                        pf_time: cfg.pf_time,
                        output_file: Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
                        pin_core: tctx.next(),
                    }
                )?
            );

            // let _ = spawn_handle0.join()?;
        }
        Workload::Memcached => {
            // // Measure host stats with perf while the workload is running. We measure at the beginning
            // // of the workload and later in the workload after the "cliff".
            // const PERF_MEASURE_TIME: usize = 50; // seconds
            // const PERF_LATE_DELAY_MS: usize = 85 * 1000; // ms

            // let perf_output_early = settings.gen_file_name("perfdata0");
            // let perf_output_late = settings.gen_file_name("perfdata1");

            // let spawn_handle0 = ushell.spawn(cmd!(
            //     "sudo taskset -c 2 {}/tools/perf/perf stat -C 0 -I 1000 \
            //      -e 'cycles,cache-misses,dTLB-load-misses,dTLB-store-misses,\
            //      page-faults,context-switches,vmscan:*,kvm:*' -o {} sleep {}",
            //     zerosim_path_host,
            //     dir!(HOSTNAME_SHARED_RESULTS_DIR,
            //     perf_output_early),
            //     PERF_MEASURE_TIME,
            // ))?;

            // let spawn_handle1 = ushell.spawn(cmd!(
            //     "sudo taskset -c 2 {}/tools/perf/perf stat -C 0 -I 1000 -D {} \
            //      -e 'cycles,cache-misses,dTLB-load-misses,dTLB-store-misses,\
            //      page-faults,context-switches,vmscan:*,kvm:*' -o {} sleep {}",
            //     zerosim_path_host,
            //     PERF_LATE_DELAY_MS,
            //     dir!(HOSTNAME_SHARED_RESULTS_DIR,
            //     perf_output_late),
            //     PERF_MEASURE_TIME,
            // ))?;

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
                        server_size_mb: cfg.size << 10,
                        wk_size_gb: cfg.size,
                        freq: Some(freq),
                        allow_oom: true,
                        pf_time: cfg.pf_time,
                        output_file: Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
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

            // let _ = spawn_handle0.join()?;
            // let _ = spawn_handle1.join()?;
        }
        Workload::Locality => {
            // const PERF_MEASURE_TIME: usize = 960; // seconds

            // let perf_output_early = settings.gen_file_name("perfdata0");
            // let spawn_handle0 = ushell.spawn(cmd!(
            //     "sudo taskset -c 3 {}/tools/perf/perf stat -C 0 -I 1000 \
            //      -e 'cycles,cache-misses,dTLB-load-misses,dTLB-store-misses,\
            //      page-faults,context-switches,vmscan:*,kvm:*' -o {} sleep {}",
            //     zerosim_path_host,
            //     dir!(HOSTNAME_SHARED_RESULTS_DIR,
            //     perf_output_early),
            //     PERF_MEASURE_TIME,
            // ))?;

            let trace_output_local = cfg.gen_file_name("tracelocal");
            let trace_output_nonlocal = cfg.gen_file_name("tracenonlocal");
            let spawn_handle0 = ushell.spawn(cmd!(
                "sudo taskset -c 3 {}/target/release/zerosim-trace trace {} {} {} -t {}",
                dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_TRACE_SUBMODULE),
                500,     // interval
                100_000, // buffer size
                dir!(HOSTNAME_SHARED_RESULTS_DIR, trace_output_local),
                cfg.pf_time.unwrap(),
            ))?;

            let output_local = cfg.gen_file_name("local");
            let output_nonlocal = cfg.gen_file_name("nonlocal");

            // Then, run the actual experiment.
            // 1) Do local accesses
            // 2) Do non-local accesses
            time!(
                timers,
                "Workload 1",
                run_locality_mem_access(
                    &vshell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Local,
                        n: LOCALITY_N,
                        threads: None,
                        output_file: &dir!(VAGRANT_RESULTS_DIR, output_local),
                    }
                )?
            );

            let _ = spawn_handle0.join().1?;

            let spawn_handle0 = ushell.spawn(cmd!(
                "sudo taskset -c 3 {}/target/release/zerosim-trace trace {} {} {} -t {}",
                dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_TRACE_SUBMODULE),
                500,     // interval
                100_000, // buffer size
                dir!(HOSTNAME_SHARED_RESULTS_DIR, trace_output_nonlocal),
                cfg.pf_time.unwrap(),
            ))?;

            time!(
                timers,
                "Workload 2",
                run_locality_mem_access(
                    &vshell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Random,
                        n: LOCALITY_N,
                        threads: None,
                        output_file: &dir!(VAGRANT_RESULTS_DIR, output_nonlocal),
                    }
                )?
            );

            let _ = spawn_handle0.join().1?;
        }

        Workload::HiBenchWordcount => {
            // Hadoop should be run as non-root user.
            let vshell = crate::exp_0sim::connect_to_vagrant_as_user(&login.host)?;

            let zerosim_hadoop = dir!(zerosim_path, ZEROSIM_BENCHMARKS_DIR, ZEROSIM_HADOOP_PATH);
            let hibench_home = dir!(&zerosim_hadoop, "HiBench");

            // Start hadoop
            vshell.run(cmd!("bash -x ./start-all-standalone.sh").cwd(&zerosim_hadoop))?;

            // Prepare hadoop input
            vshell.run(
                cmd!("./bin/workloads/micro/wordcount/prepare/prepare.sh").cwd(&hibench_home),
            )?;

            // Run workload
            vshell.run(cmd!("./bin/workloads/micro/wordcount/hadoop/run.sh").cwd(&hibench_home))?;

            // Stop hadoop
            vshell.run(cmd!("bash -x ./stop-all-standalone.sh").cwd(&zerosim_hadoop))?;
        }
    }

    ushell.run(cmd!("date"))?;

    vshell.run(cmd!(
        "echo -e '{}' > {}",
        escape_for_bash(&crate::timings_str(timers.as_slice())),
        dir!(VAGRANT_RESULTS_DIR, time_file)
    ))?;

    crate::exp_0sim::gen_standard_sim_output(&sim_file, &ushell, &vshell)?;

    let glob = cfg.gen_file_name("");
    println!("RESULTS: {}", dir!(HOSTNAME_SHARED_RESULTS_DIR, glob));

    Ok(())
}
