//! Run the given YCSB workload on the remote machine in simulation and record its results.
//!
//! TODO: also collect a memory trace and record mm stats.
//!
//! Requires `setup00000`.

use clap::clap_app;

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

use crate::{
    common::{
        exp_0sim::*,
        get_cpu_freq,
        output::OutputManager,
        paths::{setup00000::*, *},
        workloads::{
            run_ycsb_workload, MemcachedWorkloadConfig, Pintool, RedisWorkloadConfig, TasksetCtx,
            TimeMmapTouchConfig, TimeMmapTouchPattern, YcsbConfig, YcsbSystem, YcsbWorkload,
        },
    },
    settings,
};

pub fn cli_options() -> clap::App<'static, 'static> {
    fn is_usize(s: String) -> Result<(), String> {
        s.as_str()
            .parse::<usize>()
            .map(|_| ())
            .map_err(|e| format!("{:?}", e))
    }

    clap_app! { exp00011 =>
        (about: "Run experiment 00011. Requires `sudo`.")
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
        (@group WORKLOAD =>
            (@attributes +required)
            (@arg WKA: --a
             "Run YCSB core workload A.")
            (@arg WKB: --b
             "Run YCSB core workload B.")
            (@arg WKC: --c
             "Run YCSB core workload C.")
            (@arg WKD: --d
             "Run YCSB core workload D.")
            (@arg WKE: --e
             "Run YCSB core workload E.")
            (@arg WKF: --f
             "Run YCSB core workload F.")
        )
        (@group SYSTEM =>
            (@attributes +required)
            (@arg MEMCACHED: --memcached
             "Use memcached as the YCSB backend.")
            (@arg REDIS: --redis
             "Use redis as the YCSB backend.")
            (@arg KC: --kyotocabinet
             "Use kyotocabinet as the YCSB backend.")
        )
    }
}

pub fn run(print_results_path: bool, sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let vm_size = sub_m.value_of("VMSIZE").unwrap().parse::<usize>().unwrap();
    let cores = sub_m.value_of("CORES").unwrap().parse::<usize>().unwrap();

    let workload = match () {
        () if sub_m.is_present("WKA") => YcsbWorkload::A,
        () if sub_m.is_present("WKB") => YcsbWorkload::B,
        () if sub_m.is_present("WKC") => YcsbWorkload::C,
        () if sub_m.is_present("WKD") => YcsbWorkload::D,
        () if sub_m.is_present("WKE") => YcsbWorkload::E,
        () if sub_m.is_present("WKF") => YcsbWorkload::F,
        _ => unreachable!(),
    };

    let system = match () {
        () if sub_m.is_present("MEMCACHED") => YcsbSystem::Memcached,
        () if sub_m.is_present("REDIS") => YcsbSystem::Redis,
        () if sub_m.is_present("KC") => YcsbSystem::KyotoCabinet,
        _ => unreachable!(),
    };

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = crate::common::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::common::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::common::get_remote_research_settings(&ushell)?;

    let settings = settings! {
        * workload: workload,
        * system: system,
        exp: 11,

        * vm_size: vm_size,
        (cores > 1) cores: cores,

        zswap_max_pool_percent: 50,

        username: login.username,
        host: login.hostname,

        local_git_hash: local_git_hash,
        remote_git_hash: remote_git_hash,

        remote_research_settings: remote_research_settings,
    };

    run_inner(print_results_path, &login, settings)
}

/// Run the experiment using the settings passed. Note that because the only thing we are passed
/// are the settings, we know that there is no information that is not recorded in the settings
/// file.
fn run_inner<A>(
    print_results_path: bool,
    login: &Login<A>,
    settings: OutputManager,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    let vm_size = settings.get::<usize>("vm_size");
    let cores = settings.get::<usize>("cores");
    let workload = settings.get::<YcsbWorkload>("workload");
    let system = settings.get::<YcsbSystem>("system");
    let zswap_max_pool_percent = settings.get::<usize>("zswap_max_pool_percent");

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
            vm_size,
            cores,
            /* fast */ true,
            ZEROSIM_SKIP_HALT,
            ZEROSIM_LAPIC_ADJUST,
        )?
    );

    // Environment
    ZeroSim::turn_on_zswap(&mut ushell)?;
    ZeroSim::zswap_max_pool_percent(&ushell, zswap_max_pool_percent)?;

    let zerosim_exp_path = &dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );

    // Get the amount of memory the guest thinks it has (in GB).
    let size = vshell
        .run(cmd!("grep MemAvailable /proc/meminfo | awk '{{print $2}}'").use_bash())?
        .stdout
        .trim()
        .parse::<usize>()
        .unwrap()
        >> 20;

    let (output_file, params_file, time_file, sim_file) = settings.gen_standard_names();
    let params = serde_json::to_string(&settings)?;

    let pin_path = dir!(
        "/home/vagrant",
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_MEMBUFFER_EXTRACT_SUBMODULE,
        "pin"
    );

    vshell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(VAGRANT_RESULTS_DIR, params_file)
    ))?;

    // Run the workload.
    time!(
        timers,
        "Workload",
        run_ycsb_workload(
            &vshell,
            YcsbConfig {
                workload,
                system,
                ycsb_path: &dir!(
                    "/home/vagrant",
                    RESEARCH_WORKSPACE_PATH,
                    ZEROSIM_YCSB_SUBMODULE
                ),
                memcached: Some(MemcachedWorkloadConfig {
                    user: "vagrant",
                    exp_dir: zerosim_exp_path,
                    memcached: &dir!(
                        "/home/vagrant",
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_MEMCACHED_SUBMODULE
                    ),
                    allow_oom: true,
                    server_pin_core: None,
                    server_size_mb: size << 10,
                    pintool: None, // TODO

                    // Ignored:
                    wk_size_gb: 0,
                    freq: None,
                    pf_time: None,
                    output_file: None,
                    eager: false,
                    client_pin_core: 0,
                })
            }
        )?
    );

    ushell.run(cmd!("date"))?;

    vshell.run(cmd!(
        "echo -e '{}' > {}",
        crate::common::timings_str(timers.as_slice()),
        dir!(VAGRANT_RESULTS_DIR, time_file)
    ))?;

    crate::common::exp_0sim::gen_standard_sim_output(&sim_file, &ushell, &vshell)?;

    if print_results_path {
        let glob = settings.gen_file_name("*");
        println!("RESULTS: {}", dir!(HOSTNAME_SHARED_RESULTS_DIR, glob));
    }

    Ok(())
}
