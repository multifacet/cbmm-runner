//! Setup the given host (not test VM) using the kernel compiled from the given kernel source.
//! (If you want to set up a VM, use setup 2.)
//!
//! Requires `setup00000` for dependencies, etc.

use clap::clap_app;

use crate::{
    cli::setup_kernel,
    downloads::{download_and_extract, Artifact},
    exp_0sim::*,
    get_user_home_dir,
    paths::*,
    KernelBaseConfigSource, KernelConfig, KernelPkgType, KernelSrc, Login,
};

use spurs::{cmd, Execute, SshShell};

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

    let (git_repo, commitish, kernel_config, _secret, compiler) =
        setup_kernel::parse_cli_options(sub_m);

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
    let kernel_localversion = crate::gen_local_version(commitish, git_hash);

    crate::build_kernel(
        &ushell,
        KernelSrc::Git {
            repo_path: kernel_path.clone(),
            commitish: commitish.into(),
        },
        KernelConfig {
            base_config: KernelBaseConfigSource::Path(config.into()),
            extra_options: &kernel_config,
        },
        Some(&kernel_localversion),
        KernelPkgType::Rpm,
        compiler,
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

    // Install SAS driver if needed.
    install_mpt3sas_driver_if_needed(&ushell, &user_home, &kernel_path, &kernel_localversion)?;

    Ok(())
}

/// On machines that have SAS drives, you need an appropriate SAS driver. Otherwise, you won't be
/// able to use the device, and consequently, won't be able to boot. For the c220g5 cloudlab
/// machines, the required driver is mpt3sas, but the version bundled with various older kernels
/// doesn't work for some reason. Instead, we need to download and install a more recent version.
///
/// This function checks if an updated driver is needed, and if so, downloads and installs one.
pub fn install_mpt3sas_driver_if_needed(
    shell: &SshShell,
    user_home: &str,
    kernel_path: &str,
    kernel_localversion: &str,
) -> Result<(), failure::Error> {
    const KNOWN_WORKING_MAJOR_VERSION: usize = 22;

    // Check version of driver.
    let current_major_version = shell
        .run(cmd!(
            "cat {}/drivers/scsi/mpt3sas/mpt3sas_base.h |\
            grep MPT3SAS_MAJOR_VERSION |\
            awk '{{print $3}}'",
            kernel_path
        ))?
        .stdout
        .trim()
        .parse::<usize>()?;

    if current_major_version >= KNOWN_WORKING_MAJOR_VERSION {
        // Current installed driver is fine.
        return Ok(());
    }

    // Need to upgrade driver.

    // Get tarball...
    download_and_extract(shell, Artifact::Mpt3sas, user_home, Some("mpt3sas"))?;

    // Need to get the full kernel version name.
    let kernel_localversion = shell
        .run(cmd!(
            "str=`basename /boot/initramfs-*{}.img .img` ; echo -n ${{str#*-}}",
            kernel_localversion
        ))?
        .stdout;

    // Build and install kernel module.
    let driver_path = dir!(user_home, "mpt3sas");
    shell.run(
        cmd!(
            "make -C {}/kbuild KERNELRELEASE={} M=`pwd`",
            kernel_path,
            kernel_localversion
        )
        .cwd(&driver_path),
    )?;
    shell.run(
        cmd!(
            "sudo make -C {}/kbuild KERNELRELEASE={} M=`pwd` modules_install",
            kernel_path,
            kernel_localversion
        )
        .cwd(&driver_path),
    )?;

    // Make a new initramfs, so the system can use the driver at boot time.
    shell.run(cmd!(
        "sudo cp /boot/initramfs-{}.img{{,.bak}}",
        kernel_localversion
    ))?;
    shell.run(cmd!(
        "sudo dracut --force-drivers \
         'sg sd_mod raid_class scsi_transport_sas mpt3sas' \
         --kver {} --force",
        kernel_localversion
    ))?;

    Ok(())
}
