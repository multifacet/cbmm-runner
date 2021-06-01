//! Setup the given test VM using the kernel compiled from the given kernel source.
//!
//! Requires `setup00000`.

use clap::clap_app;

use crate::{
    cli::setup_kernel,
    dir,
    exp_0sim::*,
    get_user_home_dir,
    paths::{setup00000::*, setup00001::*, *},
    with_shell, KernelBaseConfigSource, KernelConfig, KernelPkgType, KernelSrc, Login,
};

use spurs::{cmd, Execute};

pub const GUEST_SWAP_GBS: usize = 10;

pub fn cli_options() -> clap::App<'static, 'static> {
    let app = clap_app! { setup00002 =>
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
    let (ushell, vshell) =
        connect_and_setup_host_and_vagrant(&login, 20, 1, ZEROSIM_SKIP_HALT, ZEROSIM_LAPIC_ADJUST)?;

    // Disable TSC offsetting so that setup runs faster
    ZeroSim::tsc_offsetting(&ushell, false)?;

    // Clone the given kernel, if needed.
    let kernel_path = pathify(&git_repo, commitish);
    ushell.run(cmd!(
        "[ -e {} ] || git clone {} {}",
        kernel_path,
        &git_repo,
        kernel_path
    ))?;

    // Install the kernel on the guest.
    //
    // Building the kernel on the guest is painful, so we will build it on the host and copy it to
    // the guest via NFS.
    let user_home = &get_user_home_dir(&ushell)?;

    let git_hash = ushell.run(cmd!("git rev-parse HEAD").cwd(RESEARCH_WORKSPACE_PATH))?;
    let git_hash = git_hash.stdout.trim();

    let guest_config = vshell
        .run(cmd!("ls -1 /boot/config-* | head -n1").use_bash())?
        .stdout;
    let guest_config = guest_config.trim();
    vshell.run(cmd!("cp {} {}", guest_config, VAGRANT_SHARED_DIR))?;

    let guest_config_base_name = std::path::Path::new(guest_config).file_name().unwrap();

    crate::build_kernel(
        &ushell,
        KernelSrc::Git {
            repo_path: kernel_path,
            commitish: commitish.into(),
        },
        KernelConfig {
            base_config: KernelBaseConfigSource::Path(dir!(
                HOSTNAME_SHARED_DIR,
                guest_config_base_name.to_str().unwrap()
            )),
            extra_options: &kernel_config,
        },
        Some(&crate::gen_local_version(commitish, git_hash)),
        KernelPkgType::Rpm,
        /* cpupower */ false,
    )?;

    // Install on the guest. To do this, we need the guest to be up and connected to NFS, so we can
    // copy the RPM over.
    let kernel_rpm = ushell
        .run(
            cmd!(
                "basename `ls -Art {}/rpmbuild/RPMS/x86_64/ | grep -v headers | tail -n 1`",
                user_home
            )
            .use_bash(),
        )?
        .stdout;
    let kernel_rpm = kernel_rpm.trim();

    ushell.run(cmd!(
        "cp {}/rpmbuild/RPMS/x86_64/{} {}/vm_shared/",
        user_home,
        kernel_rpm,
        user_home
    ))?;

    vshell.run(cmd!(
        "sudo rpm -ivh --force /vagrant/vm_shared/{}",
        kernel_rpm
    ))?;

    // create a swap device if it doesn't exist already. Note that on XFS, fallocate produces files
    // with holes, so we need to manually fill them (slow and annoying, but there isn't another
    // way, unfortunately).
    with_shell! { vshell =>
        cmd!(
            "[ -e {} ] || dd if=/dev/zero of={} bs=1G count={}",
            VAGRANT_GUEST_SWAPFILE,
            VAGRANT_GUEST_SWAPFILE,
            GUEST_SWAP_GBS,
        )
        .use_bash(),
        cmd!("mkswap {}", VAGRANT_GUEST_SWAPFILE),
        cmd!("sudo chmod 0600 {}", VAGRANT_GUEST_SWAPFILE),
        cmd!("sudo chown root:root {}", VAGRANT_GUEST_SWAPFILE),
    }
    crate::set_remote_research_setting(&ushell, "guest_swap", VAGRANT_GUEST_SWAPFILE)?;

    // update grub to choose this entry (new kernel) by default
    vshell.run(cmd!("sudo grub2-set-default 0"))?;

    // We need to sync and shut down properly to make sure the boot section of the virtual drive is
    // not corrupted. If it is corrupted, you need to basically recreate the VM :(
    vshell.run(cmd!("sync"))?;
    ushell.run(cmd!("sync"))?;

    let _ = vshell.run(cmd!("sudo poweroff"));

    Ok(())
}
