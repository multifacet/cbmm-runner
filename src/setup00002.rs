//! Setup the given cloudlab node such that it is using the kernel compiled from the given kernel
//! branch.
//!
//! Requires `setup00000`.

use spurs::{
    cmd,
    ssh::{Execute, SshShell},
};

use crate::common::{
    setup00002::{GITHUB_CLONE_USERNAME, LINUX_KERNEL_SRC_REPO, ZEROSIM_EXPERIMENTS_SRC_REPO},
    GitHubRepo, Login,
};

pub fn run<A>(
    dry_run: bool,
    login: &Login<A>,
    git_branch: Option<&str>,
    token: Option<&str>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug,
{
    // Connect to the remote
    let mut ushell = SshShell::with_default_key(login.username.as_str(), &login.host)?;
    if dry_run {
        ushell.toggle_dry_run();
    }

    if let Some(git_branch) = git_branch {
        let zerosim_repo = GitHubRepo::Https {
            repo: LINUX_KERNEL_SRC_REPO.into(),
            token: token.map(|t| (GITHUB_CLONE_USERNAME.into(), t.into())),
        };

        // Build and install the required kernel from source.
        crate::common::setup00000::build_kernel_rpm(
            dry_run,
            &ushell,
            login,
            zerosim_repo,
            git_branch,
            &[
                ("CONFIG_PAGE_TABLE_ISOLATION", false),
                ("CONFIG_RETPOLINE", false),
                ("CONFIG_FRAME_POINTER", true),
            ],
            "exp",
        )?;

        let kernel_rpm = ushell
            .run(
                cmd!("ls -t1 | head -n2 | sort | tail -n1")
                    .use_bash()
                    .cwd(&format!(
                        "/users/{}/rpmbuild/RPMS/x86_64/",
                        login.username.as_str()
                    )),
            )?
            .stdout;
        let kernel_rpm = kernel_rpm.trim();

        ushell.run(cmd!(
            "sudo rpm -ivh --force /users/{}/rpmbuild/RPMS/x86_64/{}",
            login.username.as_str(),
            kernel_rpm
        ))?;

        // update grub to choose this entry (new kernel) by default
        ushell.run(cmd!("sudo grub2-set-default 0"))?;
    }

    // Install stuff
    ushell.run(spurs::centos::yum_install(&[
        "vim",
        "git",
        "memcached",
        "gcc",
        "libcgroup",
        "libcgroup-tools",
    ]))?;

    ushell.run(cmd!("curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly --no-modify-path -y").use_bash().no_pty())?;

    // Install benchmarks
    let zerosim_exp_repo = GitHubRepo::Https {
        repo: ZEROSIM_EXPERIMENTS_SRC_REPO.into(),
        token: token.map(|t| (GITHUB_CLONE_USERNAME.into(), t.into())),
    };

    ushell.run(cmd!("git clone {} 0sim-experiments", zerosim_exp_repo).cwd("/home/vagrant/"))?;

    ushell.run(
        cmd!(
            "/users/{}/.cargo/bin/cargo build --release",
            login.username.as_str()
        )
        .cwd(&format!("/users/{}/paperexp", login.username.as_str())),
    )?;

    Ok(())
}
