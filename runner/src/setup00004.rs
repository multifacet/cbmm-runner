//! Set up the given host using HawkEye.
//!
//! Requires `setup00000` for dependencies, etc.

use clap::clap_app;

use crate::{
    exp_0sim::*, get_user_home_dir, paths::*, with_shell, KernelBaseConfigSource, KernelConfig,
    KernelPkgType, KernelSrc, Login,
};

use spurs::{cmd, Execute};

const HAWKEYE_GIT_REPO: &str = "https://github.com/mark-i-m/HawkEye";
const HAWKEYE_X86_PROFILE_REPO: &str = "https://github.com/mark-i-m/x86-MMU-Profiler";

const HAWKEYE_BRANCH: &str = "ohp";

const HAWKEYE_KERNEL_CONFIG: &[(&str, bool)] = &[
    ("CONFIG_TRANSPARENT_HUGEPAGE", true),
    ("CONFIG_PAGE_TABLE_ISOLATION", false),
    ("CONFIG_RETPOLINE", false),
    ("CONFIG_GDB_SCRIPTS", true),
    ("CONFIG_FRAME_POINTERS", true),
    ("CONFIG_IKHEADERS", true),
    ("CONFIG_SLAB_FREELIST_RANDOM", true),
    ("CONFIG_SHUFFLE_PAGE_ALLOCATOR", true),
];

pub fn cli_options() -> clap::App<'static, 'static> {
    let app = clap_app! { setup00004 =>
        (about: "Sets up the given _centos_ with the HawkEye kernel and tools. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@setting TrailingVarArg)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
    };

    app
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    // Connect to the remote.
    let mut ushell = connect_and_setup_host_only(&login)?;

    // Clone the given kernel, if needed.
    ushell.run(cmd!("[ -e HawkEye/ ] || git clone {}", HAWKEYE_GIT_REPO))?;
    ushell.run(cmd!(
        "[ -e x86-MMU-Profiler/ ] || git clone {}",
        HAWKEYE_X86_PROFILE_REPO
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
            repo_path: "HawkEye".into(),
            commitish: HAWKEYE_BRANCH.into(),
        },
        KernelConfig {
            base_config: KernelBaseConfigSource::Path(config.into()),
            extra_options: HAWKEYE_KERNEL_CONFIG,
        },
        Some(&crate::gen_local_version(HAWKEYE_BRANCH, git_hash)),
        KernelPkgType::Rpm,
        None,
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

    // Reboot so the new kernel is running when we build modules.
    spurs_util::reboot(&mut ushell, /* dry_run */ false)?;

    // Build kernel modules.
    //
    // For some reason, it fails the first time...
    let nprocess = crate::get_num_cores(&ushell)?;
    with_shell! { ushell in "HawkEye/kbuild" =>
        cmd!("make CC=/usr/bin/gcc M=hawkeye_modules/async-zero"),
        cmd!("make CC=/usr/bin/gcc M=hawkeye_modules/async-zero"),
        cmd!("make CC=/usr/bin/gcc M=hawkeye_modules/bloat_recovery"),
        cmd!("make CC=/usr/bin/gcc M=hawkeye_modules/bloat_recovery"),
    };

    // Build userspace profiling tool
    ushell.run(cmd!("make -j {}", nprocess).cwd("x86-MMU-Profiler"))?;

    Ok(())
}
