//! Boot the kernel and dump the contents of `/proc/ktask_instrumentation`.
//!
//! Requires `setup00000` followed by `setup00001` with the `markm_instrument_ktask` or
//! `markm_instrument_mem_init` kernel.

use clap::clap_app;

use crate::{
    cli::validator,
    dir,
    exp_0sim::*,
    output::{Parametrize, Timestamp},
    paths::setup00000::*,
    time,
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
    #[name]
    cores: usize,

    #[name(self.ktask_div.is_some())]
    ktask_div: Option<usize>,

    username: String,
    host: String,

    local_git_hash: String,
    remote_git_hash: String,

    remote_research_settings: std::collections::BTreeMap<String, String>,

    #[timestamp]
    timestamp: Timestamp,
}

pub fn cli_options() -> clap::App<'static, 'static> {
    clap_app! { exp00006 =>
        (about: "Run experiment 00006. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@arg VMSIZE: +takes_value {validator::is::<usize>} +required
         "The number of GBs of the VM")
        (@arg CORES: +takes_value {validator::is::<usize>} +required
         "The number of cores of the VM")
        (@group KTASK_DIV =>
            (@attributes +required)
            (@arg DIV: +takes_value {validator::is::<usize>}
             "The scaling factor to pass a boot parameter. The max number of threads \
              in ktask is set to `CORES / KTASK_DIV`. 4 is the default for \
              normal ktask.")
            (@arg NO_KTASK: --no_ktask
             "Measure boot without ktask.")
        )
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
    let ktask_div = sub_m.value_of("DIV").map(|s| s.parse::<usize>().unwrap());

    let ushell = SshShell::with_default_key(&login.username, &login.host)?;
    let local_git_hash = crate::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (
            6,
            if ktask_div.is_some() {
                "ktask_boot_mem_init"
            } else {
                "boot_mem_init"
            }
            .into(),
        ),

        vm_size,
        cores,

        ktask_div,

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
    // Collect timers on VM
    let mut timers = vec![];

    // We first need to set the guest kernel boot param.
    if let Some(ktask_div) = cfg.ktask_div {
        let ushell = SshShell::with_default_key(login.username, login.hostname)?;
        let vshell = time!(
            timers,
            "Start VM (for boot param setting)",
            start_vagrant(
                &ushell,
                &login.host,
                /* RAM */ 10,
                /* cores */ 1,
                /* fast */ true,
                ZEROSIM_SKIP_HALT,
                ZEROSIM_LAPIC_ADJUST,
            )?
        );

        set_kernel_boot_param(
            &vshell,
            "ktask_mem_ncores_div",
            Some(&format!("{}", ktask_div)),
        )?;

        // Allow-error doesn't work because there will be a transport error, not a command failure.
        let _ = vshell.run(cmd!("sudo poweroff"));
    }

    // Reboot
    initial_reboot(&login)?;

    // Connect
    let ushell = connect_and_setup_host_only(&login)?;

    let vshell = time!(
        timers,
        "Start VM",
        start_vagrant(
            &ushell,
            &login.host,
            cfg.vm_size,
            cfg.cores,
            /* fast */ false,
            ZEROSIM_SKIP_HALT,
            ZEROSIM_LAPIC_ADJUST,
        )?
    );

    let (output_file, params_file, time_file, sim_file) = cfg.gen_standard_names();
    let params = serde_json::to_string(&cfg)?;

    vshell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(VAGRANT_RESULTS_DIR, params_file)
    ))?;

    vshell.run(cmd!(
        "cat /proc/ktask_instrumentation > {}",
        dir!(VAGRANT_RESULTS_DIR, output_file)
    ))?;

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
