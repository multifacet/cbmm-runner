//! Setup the given host (not test VM) using the kernel compiled from the given kernel source.
//! (If you want to set up a VM, use setup 2.)
//!
//! Requires `setup00000` for dependencies, etc.

use clap::clap_app;

use crate::{
    cli::setup_kernel, exp_0sim::*, get_user_home_dir, paths::*, KernelBaseConfigSource,
    KernelConfig, KernelPkgType, KernelSrc, Login,
};

use spurs::{cmd, Execute};

pub fn cli_options() -> clap::App<'static, 'static> {
    let app = clap_app! { setup00003 =>
        (about: "Sets up the given _centos_ with the given kernel. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@setting TrailingVarArg)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
    };

    let app = setup_kernel::add_cli_options(app);

    app
}

/// Turn `repo` and `branch` into something that is unlikely to cause problems if we use it in a path name.
fn pathify(repo: &str, branch: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let s = format!("{}{}", repo, branch);
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("kernel-{:x}", h.finish())
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let (git_repo, commitish, kernel_config, _secret) = setup_kernel::parse_cli_options(sub_m);

    // Connect to the remote.
    let ushell = connect_and_setup_host_only(&login)?;

    // Clone the given kernel, if needed.
    let kernel_path = pathify(&git_repo, commitish);
    ushell.run(cmd!(
        "[ -e {} ] || git clone {} {}",
        kernel_path,
        &git_repo,
        kernel_path
    ))?;

    // Install the kernel.
    let user_home = &get_user_home_dir(&ushell)?;

    let git_hash = ushell.run(cmd!("git rev-parse HEAD").cwd(RESEARCH_WORKSPACE_PATH))?;
    let git_hash = git_hash.stdout.trim();

    let config = ushell
        .run(cmd!("ls -1 /boot/config-* | head -n1").use_bash())?
        .stdout;
    let config = config.trim();

    crate::build_kernel(
        &ushell,
        KernelSrc::Git {
            repo_path: kernel_path,
            commitish: commitish.into(),
        },
        KernelConfig {
            base_config: KernelBaseConfigSource::Path(config.into()),
            extra_options: &kernel_config,
        },
        Some(&crate::gen_local_version(commitish, git_hash)),
        KernelPkgType::Rpm,
        /* cpupower */ true,
    )?;

    // Install on the host.
    let kernel_rpm = ushell
        .run(
            cmd!(
                "ls -Art {}/rpmbuild/RPMS/x86_64/ | grep -v headers | tail -n 1",
                user_home
            )
            .use_bash(),
        )?
        .stdout;
    let kernel_rpm = kernel_rpm.trim();

    ushell.run(cmd!(
        "sudo rpm -ivh --force {}/rpmbuild/RPMS/x86_64/{}",
        user_home,
        kernel_rpm
    ))?;

    // update grub to choose this entry (new kernel) by default
    ushell.run(cmd!("sudo grub2-set-default 0"))?;
    ushell.run(cmd!("sync"))?;

    Ok(())
}
