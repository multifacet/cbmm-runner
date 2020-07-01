//! Setup the given host (not test VM) using the kernel compiled from the given kernel source.
//! (If you want to set up a VM, use setup 2.)
//!
//! Requires `setup00000` for dependencies, etc.

use clap::clap_app;

use runner::{
    exp_0sim::*, get_user_home_dir, paths::*, GitRepo, KernelBaseConfigSource, KernelConfig,
    KernelPkgType, KernelSrc, Login,
};

use spurs::{cmd, Execute};

pub fn cli_options() -> clap::App<'static, 'static> {
    clap_app! { setup00003 =>
        (about: "Sets up the given _centos_ with the given kernel. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@setting TrailingVarArg)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@group GIT_REPO =>
            (@attributes +required)
            (@arg HTTPS: --https +takes_value
             "The git repository to compile the kernel from as an HTTPS URL.")
            (@arg SSH: --ssh +takes_value
             "The git repository to compile the kernel from as an SSH address.")
        )
        (@arg COMMITISH: +required +takes_value
         "The git branch/hash/tag to compile the kernel from (e.g. master or v4.10)")
        (@arg SECRET: --secret +takes_value requires[HTTPS] requires[GIT_USERNAME]
         "A secret token for accessing a private repository")
        (@arg GIT_USERNAME: --username +takes_value requires[HTTPS] requires[SECRET]
         "A username for accessing a private repository")
        (@arg CONFIGS: ... +allow_hyphen_values {validate_config_option}
         "Space separated list of Linux kernel configuration options, prefixed by \
         + to enable and - to disable. For example, +CONFIG_ZSWAP or \
         -CONFIG_PAGE_TABLE_ISOLATION")
    }
}

fn validate_config_option(opt: String) -> Result<(), String> {
    parse_config_option(&opt)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn parse_config_option(opt: &str) -> Result<(&str, bool), failure::Error> {
    fn check(s: &str) -> Result<&str, failure::Error> {
        if s.is_empty() {
            Err(failure::format_err!("Empty string is not a valid option"))
        } else {
            for c in s.chars() {
                if !c.is_ascii_alphanumeric() && c != '_' {
                    return Err(failure::format_err!("Invalid config name \"{}\"", s));
                }
            }
            Ok(s)
        }
    }

    if opt.is_empty() {
        Err(failure::format_err!("Empty string is not a valid option"))
    } else {
        match &opt[0..1] {
            "+" => Ok((check(&opt[1..])?, true)),
            "-" => Ok((check(&opt[1..])?, false)),
            _ => Err(failure::format_err!(
                "Kernel config option must be prefixed with + or -"
            )),
        }
    }
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
    let secret = sub_m.value_of("SECRET");
    let git_repo = {
        let https = sub_m.value_of("HTTPS");
        let ssh = sub_m.value_of("SSH");
        let username = sub_m.value_of("GIT_USERNAME");

        match (https, ssh, secret) {
            (Some(https), None, None) => GitRepo::HttpsPublic { repo: https },
            (Some(https), None, Some(_)) => GitRepo::HttpsPrivate {
                repo: https,
                username: username.unwrap(),
            },
            (None, Some(ssh), None) => GitRepo::Ssh { repo: ssh },
            _ => unreachable!(),
        }
    }
    .git_repo_access_url(secret);
    let commitish = sub_m.value_of("COMMITISH").unwrap();
    let kernel_config: Vec<_> = sub_m
        .values_of("CONFIGS")
        .map(|values| {
            values
                .map(|arg| parse_config_option(arg).unwrap())
                .collect()
        })
        .unwrap_or_else(|| vec![]);

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

    // Install the kernel on the guest.
    //
    // Building the kernel on the guest is painful, so we will build it on the host and copy it to
    // the guest via NFS.
    let user_home = &get_user_home_dir(&ushell)?;

    let git_hash = ushell.run(cmd!("git rev-parse HEAD").cwd(RESEARCH_WORKSPACE_PATH))?;
    let git_hash = git_hash.stdout.trim();

    let config = ushell
        .run(cmd!("ls -1 /boot/config-* | head -n1").use_bash())?
        .stdout;
    let config = config.trim();

    runner::build_kernel(
        &ushell,
        KernelSrc::Git {
            repo_path: kernel_path,
            commitish: commitish.into(),
        },
        KernelConfig {
            base_config: KernelBaseConfigSource::Path(config.into()),
            extra_options: &kernel_config,
        },
        Some(&runner::gen_local_version(commitish, git_hash)),
        KernelPkgType::Rpm,
    )?;

    // Install on the guest. To do this, we need the guest to be up and connected to NFS, so we can
    // copy the RPM over.
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
