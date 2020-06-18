//! Run the time_mmap_touch or memcached_gen_data workload on the remote test machine in simulation
//! while also running a kernel build on the host machine.
//!
//! Requires `setup00000`.

use clap::clap_app;

use runner::{
    dir,
    downloads::{artifact_info, Artifact},
    exp_0sim::*,
    get_cpu_freq,
    output::{Parametrize, Timestamp},
    paths::{setup00000::*, *},
    time,
    workloads::{
        run_memcached_gen_data, run_time_mmap_touch, MemcachedWorkloadConfig, TasksetCtx,
        TimeMmapTouchConfig, TimeMmapTouchPattern,
    },
    KernelBaseConfigSource, KernelConfig, KernelPkgType, KernelSrc,
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    vm_size: usize,
    #[name(self.cores > 1)]
    cores: usize,

    pattern: Option<TimeMmapTouchPattern>,
    prefault: bool,

    #[name(self.size.is_some())]
    size: Option<usize>,
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
    fn is_usize(s: String) -> Result<(), String> {
        s.as_str()
            .parse::<usize>()
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }

    clap_app! { exp00009 =>
        (about: "Run experiment 00009. Requires `sudo`.")
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
            (@arg zeros: -z "Fill pages with zeros")
            (@arg counter: -c "Fill pages with counter values")
            (@arg memcached: -m "Run a memcached workload")
        )
        (@arg WARMUP: -w --warmup
         "Pass this flag to warmup the VM before running the main workload.")
        (@arg PREFAULT: -p --prefault
         "Pass this flag to prefault memory before running the main workload \
         (ignored for memcached).")
        (@arg SIZE: -s --size +takes_value {is_usize}
         "The number of GBs of the workload (e.g. 500)")
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

    let pattern = if sub_m.is_present("memcached") {
        None
    } else {
        Some(if sub_m.is_present("zeros") {
            TimeMmapTouchPattern::Zeros
        } else {
            TimeMmapTouchPattern::Counter
        })
    };

    let size = sub_m
        .value_of("SIZE")
        .map(|value| value.parse::<usize>().unwrap());
    let warmup = sub_m.is_present("WARMUP");
    let prefault = sub_m.is_present("PREFAULT");

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = runner::local_research_workspace_git_hash()?;
    let remote_git_hash = runner::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = runner::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (
            9,
            if pattern.is_some() {
                "time_mmap_touch_host_kbuild"
            } else {
                "memcached_gen_data_host_kbuild"
            }
            .into(),
        ),

        vm_size,
        cores,
        pattern,
        prefault,

        size,
        calibrate: false,
        warmup,

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

    // Reuse the kernel build folder we used during setup 0 to build the guest kernel. We
    // need to clean it first...
    let tarball_path: String = artifact_info(Artifact::Linux)
        .name
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".tar.xz")
        .trim_end_matches(".tgz")
        .into();
    ushell.run(cmd!("make clean").cwd(tarball_path))?;

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

    // Spawn a kernel build in another thread...
    let _handle = std::thread::spawn({
        let ushell2 = SshShell::with_default_key(login.username, &login.host)
            .expect("Unable to connect to host for kernel build");

        let kernel_info = artifact_info(Artifact::Linux);
        move || {
            runner::build_kernel(
                &ushell2,
                KernelSrc::Tar {
                    tarball_path: kernel_info.name.into(),
                },
                KernelConfig {
                    base_config: KernelBaseConfigSource::Current,
                    extra_options: &[
                        // disable spectre/meltdown mitigations
                        ("CONFIG_PAGE_TABLE_ISOLATION", false),
                        ("CONFIG_RETPOLINE", false),
                        // for `perf` stack traces
                        ("CONFIG_FRAME_POINTER", true),
                    ],
                },
                None,
                KernelPkgType::Rpm,
            )
            .expect("Kernel Build FAILED");
        }
    });

    // Run memcached or time_touch_mmap
    if let Some(pattern) = cfg.pattern {
        time!(
            timers,
            "Workload",
            run_time_mmap_touch(
                &vshell,
                &TimeMmapTouchConfig {
                    exp_dir: zerosim_exp_path,
                    pages: (size << 30) >> 12,
                    pattern: pattern,
                    prefault: cfg.prefault,
                    pf_time: None,
                    output_file: Some(&dir!(VAGRANT_RESULTS_DIR, output_file)),
                    eager: None,
                    pin_core: tctx.next(),
                }
            )?
        );
    } else {
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
                    pintool: None,
                    damon: None,
                }
            )?
        );
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
