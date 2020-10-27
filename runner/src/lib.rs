//! A library of routines commonly used in experiments.
//!
//! In honor of my friend Josh:
//!
//!  _━*━___━━___━__*___━_*___┓━╭━━━━━━━━━╮
//! __*_━━___━━___━━*____━━___┗┓|::::::^---^
//! ___━━___━*━___━━____━━*___━┗|::::|｡◕‿‿◕｡|
//! ___*━__━━_*___━━___*━━___*━━╰O­-O---O--O ╯

// Must be imported first because the other submodules use the macros defined therein.
#[macro_use]
mod macros;

#[macro_use]
pub mod output;

pub mod background;
pub mod cli;
pub mod downloads;
pub mod exp_0sim;
pub mod hadoop;
pub mod workloads;

use std::path::Path;
use std::process::Command;

use failure::ResultExt;

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};

use paths::*;

///////////////////////////////////////////////////////////////////////////////
// Location of the workspace repo.

/// The access method to use to clone the workspace repo to the _remote_. Make sure that the access
/// method works on the remote (e.g. the applicable private keys need to be installed on the remote
/// if using SSH).
/*
pub const RESEARCH_WORKSPACE_REPO: GitRepo<'_, '_> = GitRepo::HttpsPublic {
    repo: "github.com/multifacet/0sim-workspace",
};
*/

pub const RESEARCH_WORKSPACE_REPO: GitRepo<'_, '_> = GitRepo::HttpsPrivate {
    repo: "github.com/mark-i-m/research-workspace",
    username: "robo-mark-i-m",
};

/// A git repository.
#[derive(Clone, Debug)]
pub enum GitRepo<'a, 's> {
    /// Use HTTPS to clone a public repo (no access control).
    HttpsPublic {
        /// Repo https URL (e.g. `github.com/multifacet/0sim-workspace`). Note the lack of `https://`!
        repo: &'a str,
    },

    /// Use HTTPS to clone a private repo. A password or personal access token must be provided at
    /// the time of the clone.
    HttpsPrivate {
        /// Repo https URL (e.g. `github.com/multifacet/0sim-workspace`). Note the lack of `https://`!
        repo: &'a str,

        /// The username to use when cloning the repository (e.g. `robo-mark-i-m` is the github
        /// username we use).
        username: &'s str,
    },

    /// Use SSH. Not PAT is needed, and this works for public and private repos.
    Ssh {
        /// Repo git URL (e.g. `git@github.com:multifacet/0sim-workspace`)
        repo: &'s str,
    },
}

impl GitRepo<'_, '_> {
    /// Given a repository and access method, form the URL string to be passed to git.
    ///
    /// If this repository is private, then `secret` must be a Personal Access Token or password.
    /// Otherwise, this method **panics**.
    ///
    /// If this repository is public or SSH is used, then `secret` is ignored.
    pub fn git_repo_access_url(&self, secret: Option<&str>) -> String {
        match (self, secret) {
            (GitRepo::Ssh { repo }, _) => repo.to_string(),
            (GitRepo::HttpsPublic { repo }, _) => format!("https://{}", repo),
            (GitRepo::HttpsPrivate { repo, username }, Some(secret)) => {
                format!("https://{}:{}@{}", username, secret, repo)
            }
            (GitRepo::HttpsPrivate { .. }, None) => {
                panic!("No PAT or password provided for private repository.")
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

/// Information needed to log into a remote machine.
#[derive(Clone, Debug)]
pub struct Login<'u, 'h, A: std::net::ToSocketAddrs + std::fmt::Display + Clone> {
    /// A network address for the host.
    pub host: A,
    /// A human-readable address for the host. Often, this is the same as `host`.
    pub hostname: &'h str,
    /// The username to log in as.
    pub username: &'u str,
}

/// Common paths.
pub mod paths {
    /// The path at which `clone_research_workspace` clones the workspace.
    pub const RESEARCH_WORKSPACE_PATH: &str = "0sim-workspace";

    /// Path to the 0sim submodule.
    pub const ZEROSIM_KERNEL_SUBMODULE: &str = "0sim";

    /// Path to the 0sim-experiments submodule.
    pub const ZEROSIM_EXPERIMENTS_SUBMODULE: &str = "0sim-experiments";

    /// Path to the 0sim-trace submodule.
    pub const ZEROSIM_TRACE_SUBMODULE: &str = "0sim-trace";

    /// Path to the HiBench submodule.
    pub const ZEROSIM_HIBENCH_SUBMODULE: &str = "bmks/zerosim-hadoop/HiBench";

    /// Path to the memhog (numactl) submodule.
    pub const ZEROSIM_MEMHOG_SUBMODULE: &str = "bmks/numactl";

    /// Path to the metis submodule.
    pub const ZEROSIM_METIS_SUBMODULE: &str = "bmks/Metis";

    /// Path to the memcached submodule.
    pub const ZEROSIM_MEMCACHED_SUBMODULE: &str = "bmks/memcached";

    /// Path to the nullfs submodule
    pub const ZEROSIM_NULLFS_SUBMODULE: &str = "bmks/nullfs";

    /// Path to the zlib submodule
    pub const ZEROSIM_ZLIB_SUBMODULE: &str = "bmks/zlib";

    /// Path to the membuffer-extract submodule
    pub const ZEROSIM_MEMBUFFER_EXTRACT_SUBMODULE: &str = "bmks/membuffer-extract";

    /// Path to the YCSB submodule
    pub const ZEROSIM_YCSB_SUBMODULE: &str = "bmks/YCSB";

    /// Path to the graph500 submodule
    pub const ZEROSIM_GRAPH500_SUBMODULE: &str = "bmks/graph500";

    /// Path to the thp-ubmk source directory.
    pub const THP_UBMK_DIR: &str = "bmks/thp-ubmk";

    /// Path to redis.conf.
    pub const REDIS_CONF: &str = "bmks/redis.conf";

    /// Path to SPEC 2017 benchmark directory.
    pub const SPEC_2017_DIR: &str = "bmks/spec2017";

    /// Path to SPEC 2017 config.
    pub const SPEC_2017_CONF: &str = "spec-linux-x86.cfg";

    /// Path to benchmarks directory.
    pub const ZEROSIM_BENCHMARKS_DIR: &str = "bmks";

    /// Path to Hadoop benchmark stuff within the benchmarks dir.
    pub const ZEROSIM_HADOOP_PATH: &str = "zerosim-hadoop";

    /// Path to Swapnil's scripts within the benchmarks dir.
    pub const ZEROSIM_SWAPNIL_PATH: &str = "swapnil_scripts";

    /// The name of the eager paging script.
    /// - For the 0sim paper (ASPLOS '20), use `apriori_paging_set_process`.
    /// - For experiments after June 2020, use `eager_paging`.
    //pub const EAGER_PAGING_SCRIPT: &str = "apriori_paging_set_process";
    pub const EAGER_PAGING_SCRIPT: &str = "eager_paging";

    /// Path to DAMON scripts within the benchmarks dir.
    pub const DAMON_PATH: &str = "damon";

    /// Path to the `vagrant` subdirectory where `gen_vagrantfile` will do its work.
    pub const VAGRANT_SUBDIRECTORY: &str = "vagrant";

    /// The base box for vagrant for CentOS 7.
    pub const VAGRANT_CENTOS7_BOX: &str = "centos/7";

    /// The base box for vagrant for CentOS 8.
    pub const VAGRANT_CENTOS8_BOX: &str = "centos/8";

    pub mod setup00000 {
        /// The shared directory on the host.
        pub const HOSTNAME_SHARED_DIR: &str = "vm_shared/";

        /// The shared directory for results on the host.
        pub const HOSTNAME_SHARED_RESULTS_DIR: &str = "vm_shared/results/";

        /// The shared directory on the guest.
        pub const VAGRANT_SHARED_DIR: &str = "/vagrant/vm_shared/";

        /// The shared directory for results on the guest.
        pub const VAGRANT_RESULTS_DIR: &str = "/vagrant/vm_shared/results/";
    }

    pub mod setup00001 {
        /// The guest swapfile.
        pub const VAGRANT_GUEST_SWAPFILE: &str = "/home/vagrant/swap";
    }
}

/// Given an array of timings, generate a human-readable string.
pub fn timings_str(timings: &[(&str, std::time::Duration)]) -> String {
    let mut s = String::new();
    for (label, d) in timings.iter() {
        s.push_str(&format!("{}: {:?}\n", label, d));
    }
    s
}

/// Copy the given directory or files from this machine to the given remote at the given location.
/// This uses rsync via SSH to copy with compression, which often leads to significant speedups.
/// However, it will fail if the remote is not in known_hosts.
pub fn rsync_to_remote<A, P>(login: &Login<A>, from: P, to: P) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
    P: AsRef<Path>,
{
    println!(
        "Using rsync to copy files. If this fails, make sure your host is in \
         known_hosts and retry."
    );

    let mut cmd = Command::new("rsync");
    cmd.arg("-vvzP")
        .args(&["-e", "ssh -o StrictHostKeyChecking=yes"])
        .arg(from.as_ref().as_os_str())
        .arg(&format!(
            "{}@{}:{}",
            login.username,
            login.host.to_socket_addrs()?.next().unwrap().ip(),
            to.as_ref().display()
        ));

    println!("{:?}", cmd);

    let status = cmd.status()?;

    // If failure, exit with an Err(..).
    if !status.success() {
        failure::bail!("rsync failed. Exit code: {:?}", status.code());
    }

    Ok(())
}

/// Clone the 0sim-workspace and checkout the given submodules.
///
/// `secret` is a GitHub personal access token or password that is needed if a private repo is
/// being accessed via HTTPS.
///
/// If the repository is already cloned, it is updated (along with submodules).
///
/// Returns the git hash of the cloned repo.
///
/// *NOTE*: This function intentionally does not take the repo URL. It should always be the above.
pub fn clone_research_workspace(
    ushell: &SshShell,
    secret: Option<&str>,
    submodules: &[&str],
) -> Result<String, failure::Error> {
    // Check if the repo is already cloned.
    if let Ok(_hash) = research_workspace_git_hash(&ushell) {
        // If so, just update it.
        with_shell! { ushell in &dir!(RESEARCH_WORKSPACE_PATH) =>
            cmd!("git pull"),
            cmd!("git submodule update"),
        }
    } else {
        // Clone the repo.
        ushell.run(cmd!(
            "git clone {} 0sim-workspace",
            RESEARCH_WORKSPACE_REPO.git_repo_access_url(secret)
        ))?;
    }

    // Checkout submodules.
    for submodule in submodules {
        ushell.run(
            cmd!("git submodule update --init --recursive -- {}", submodule)
                .cwd(RESEARCH_WORKSPACE_PATH),
        )?;
    }

    // Get the sha hash.
    research_workspace_git_hash(ushell)
}

/// Get the git hash of the remote research workspace.
pub fn research_workspace_git_hash(ushell: &SshShell) -> Result<String, failure::Error> {
    let hash = ushell.run(cmd!("git rev-parse HEAD").cwd(RESEARCH_WORKSPACE_PATH))?;
    let hash = hash.stdout.trim();

    Ok(hash.into())
}

/// Get the git hash of the local research workspace, specifically the workspace from which the
/// runner is run. Returns `"dirty"` if the workspace has uncommitted changes.
pub fn local_research_workspace_git_hash() -> Result<String, failure::Error> {
    let is_dirty = std::process::Command::new("git")
        .args(&["diff", "--quiet"])
        .status()?
        .code()
        .expect("terminated by signal")
        == 1;

    if is_dirty {
        return Ok("dirty".into());
    }

    let output = std::process::Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()?;
    let output =
        std::str::from_utf8(&output.stdout).context("converting git hash string to UTF-8")?;
    let output = output.trim();
    Ok(output.into())
}

/// Get the path of the user's home directory.
pub fn get_user_home_dir(ushell: &SshShell) -> Result<String, failure::Error> {
    let user_home = ushell
        .run(cmd!("echo $HOME").use_bash())?
        .stdout
        .trim()
        .to_owned();
    if user_home.is_empty() {
        Err(failure::format_err!("$HOME is empty"))
    } else {
        Ok(user_home)
    }
}

/// There are some settings that are per-machine, rather than per-experiment (e.g. which devices to
/// turn on as swap devices). We keep these settings in a per-machine file called
/// `research-settings.json`, which is generated at the time of the setup.
///
/// This function sets the given setting or overwrites its current value.
pub fn set_remote_research_setting<V: Serialize>(
    ushell: &SshShell,
    setting: &str,
    value: V,
) -> Result<(), failure::Error> {
    // Make sure the file exists
    ushell.run(cmd!("touch research-settings.json"))?;

    // We don't care too much about efficiency, so whenever we update, we will just read,
    // deserialize, update, and reserialize.
    let mut settings = get_remote_research_settings(ushell)?;

    let serialized = serde_json::to_string(&value).expect("unable to serialize");
    settings.insert(setting.into(), serialized);

    let new_contents = serde_json::to_string(&settings).expect("unable to serialize");

    ushell.run(cmd!("echo '{}' > research-settings.json", new_contents))?;

    Ok(())
}

/// Return all research settings. The user can then use `get_remote_research_setting` to parse out
/// a single value.
pub fn get_remote_research_settings(
    ushell: &SshShell,
) -> Result<std::collections::BTreeMap<String, String>, failure::Error> {
    // Make sure the file exists
    ushell.run(cmd!("touch research-settings.json"))?;

    let file_contents = ushell.run(cmd!("cat research-settings.json"))?;
    let file_contents = file_contents.stdout.trim();

    if file_contents.is_empty() {
        Ok(std::collections::BTreeMap::new())
    } else {
        Ok(serde_json::from_str(file_contents).expect("unable to deserialize"))
    }
}

/// Returns the value of the given setting if it is set.
pub fn get_remote_research_setting<'s, 'd, V: Deserialize<'d>>(
    settings: &'s std::collections::BTreeMap<String, String>,
    setting: &str,
) -> Result<Option<V>, failure::Error>
where
    's: 'd,
{
    if let Some(setting) = settings.get(setting) {
        Ok(Some(
            serde_json::from_str(setting).context("deserializing remote research settings")?,
        ))
    } else {
        Ok(None)
    }
}

/// Generate a local version name from the git branch and hash.
///
/// If the branch name is longer than 15 characters, it is truncated. If the git hash is longer
/// than 15 characters, it is truncated.
pub fn gen_local_version(branch: &str, hash: &str) -> String {
    let branch_split = std::cmp::min(branch.len(), 15);
    let hash_split = std::cmp::min(hash.len(), 15);
    format!(
        "{}-{}",
        branch.split_at(branch_split).0.replace("_", "-"),
        hash.split_at(hash_split).0
    )
}

/// Generate a new vagrant domain name and update the Vagrantfile.
pub fn gen_new_vagrantdomain(shell: &SshShell, vagrant_box: &str) -> Result<(), failure::Error> {
    let vagrant_path = &format!("{}/{}", RESEARCH_WORKSPACE_PATH, VAGRANT_SUBDIRECTORY);
    let uniq = shell.run(cmd!("date | sha256sum | head -c 10"))?;
    let uniq = uniq.stdout.trim();

    with_shell! { shell in vagrant_path =>
        cmd!(
            r#"sed -i 's/^vagrant_vm_name = :test_vm$/vagrant_vm_name = :test_vm_{}/' Vagrantfile"#,
            uniq
        ),
        cmd!(
            r#"sed -i 's|^vagrant_box = .*$|vagrant_box = "{}"|' Vagrantfile"#,
            vagrant_box
        ),
    }

    Ok(())
}

/// Returns the number of processor cores on the machine.
pub fn get_num_cores(shell: &SshShell) -> Result<usize, failure::Error> {
    let nprocess = shell.run(cmd!("getconf _NPROCESSORS_ONLN"))?.stdout;
    let nprocess = nprocess.trim();

    let nprocess = nprocess
        .parse::<usize>()
        .context("parsing number of cores")?;

    Ok(nprocess)
}

/// Get the max CPU frequency of the remote in MHz.
///
/// NOTE: this is not necessarily the current CPU freq. You need to set the scaling governor.
pub fn get_cpu_freq(shell: &SshShell) -> Result<usize, failure::Error> {
    let freq =
        shell.run(cmd!("lscpu | grep 'CPU max MHz' | grep -oE '[0-9]+' | head -n1").use_bash())?;
    let alt =
        shell.run(cmd!("lscpu | grep 'CPU MHz' | grep -oE '[0-9]+' | head -n1").use_bash())?;
    if freq.stdout.trim().is_empty() {
        Ok(alt.stdout.trim().parse::<usize>().unwrap())
    } else {
        Ok(freq.stdout.trim().parse::<usize>().unwrap())
    }
}

/// Turn off ASLR.
pub fn disable_aslr(shell: &SshShell) -> Result<(), failure::Error> {
    shell.run(cmd!(
        "echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
    ))?;
    Ok(())
}

/// Allow any user to run `perf`.
pub fn perf_for_all(shell: &SshShell) -> Result<(), failure::Error> {
    shell.run(cmd!(
        "echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
    ))?;
    Ok(())
}

/// Turn on THP on the remote using the given settings. Requires `sudo`.
pub fn turn_on_thp(
    shell: &SshShell,
    transparent_hugepage_enabled: &str,
    transparent_hugepage_defrag: &str,
    transparent_hugepage_khugepaged_defrag: usize,
    transparent_hugepage_khugepaged_alloc_sleep_ms: usize,
    transparent_hugepage_khugepaged_scan_sleep_ms: usize,
) -> Result<(), failure::Error> {
    shell.run(
        cmd!(
            "echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/enabled",
            transparent_hugepage_enabled
        )
        .use_bash(),
    )?;
    shell.run(
        cmd!(
            "echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/defrag",
            transparent_hugepage_defrag
        )
        .use_bash(),
    )?;
    shell.run(
        cmd!(
            "echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/khugepaged/defrag",
            transparent_hugepage_khugepaged_defrag
        )
        .use_bash(),
    )?;
    shell.run(
        cmd!("echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/khugepaged/alloc_sleep_millisecs",
             transparent_hugepage_khugepaged_alloc_sleep_ms).use_bash(),
    )?;
    shell.run(
        cmd!("echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs",
             transparent_hugepage_khugepaged_scan_sleep_ms).use_bash(),
    )?;

    Ok(())
}

pub fn set_auto_numa(shell: &SshShell, on: bool) -> Result<(), failure::Error> {
    shell.run(cmd!(
        "echo {} | sudo tee /proc/sys/kernel/numa_balancing",
        if on { 1 } else { 0 }
    ))?;

    Ok(())
}

/// What type of package to produce from the kernel build?
pub enum KernelPkgType {
    /// `bindeb-pkg`
    Deb,
    /// `binrpm-pkg`
    Rpm,
}

/// Where to build the kernel from?
pub enum KernelSrc {
    /// The given git repo and commitish (a branch, tag, commit hash, etc, as accepted by git).
    ///
    /// The repo should already be cloned at the give path. This function will checkout the given
    /// branch, though, so the repo should be clean.
    Git {
        repo_path: String,
        commitish: String,
    },

    /// The given tarball, which will be untarred and built as is. We assume that the name of the
    /// unpacked source directory is the same as the tarball name without the `.tar.gz`, `.tar.xz`,
    /// or `.tgz` extension.
    Tar { tarball_path: String },
}

/// Where to get the base config (on top of which we will apply additional changes)?
pub enum KernelBaseConfigSource {
    /// Use `make defconfig`
    Defconfig,

    /// Use the running kernel.
    Current,

    /// Use the config from the given path.
    Path(String),
}

/// How to configure the kernel build? The config is created by taking some "base config", such as
/// the one for the running kernel, and applying some changes to it to enable or disable additional
/// options.
pub struct KernelConfig<'a> {
    pub base_config: KernelBaseConfigSource,

    /// A list of config option names that should be set or unset before building. It is the
    /// caller's responsibility to make sure that all dependencies are on too. If a config is
    /// `true` it is set to "y"; otherwise, it is unset.
    pub extra_options: &'a [(&'a str, bool)],
}

pub fn get_absolute_path(shell: &SshShell, path: &str) -> Result<String, failure::Error> {
    Ok(shell.run(cmd!("pwd").cwd(path))?.stdout.trim().into())
}

/// Build a Linux kernel package (RPM or DEB). This command does not install the new kernel.
///
/// `kernel_local_version` is the kernel `LOCALVERSION` string to pass to `make` for the RPM, if
/// any.
///
/// `cpupower` indicates whether to build and install `cpupower` (true) or not (false).
pub fn build_kernel(
    ushell: &SshShell,
    source: KernelSrc,
    config: KernelConfig<'_>,
    kernel_local_version: Option<&str>,
    pkg_type: KernelPkgType,
    cpupower: bool,
) -> Result<(), failure::Error> {
    // Check out or unpack the source code, returning its absolute path.
    let source_path = match source {
        KernelSrc::Git {
            repo_path,
            commitish,
        } => {
            ushell.run(cmd!("git fetch origin").cwd(&repo_path))?;
            ushell.run(cmd!("git checkout {}", commitish).cwd(&repo_path))?;

            // If the git HEAD is detached, we should not attempt to `git pull` the latest changes,
            // as that doesn't make any sense.
            let is_detached = ushell
                .run(cmd!("git symbolic-ref -q HEAD").cwd(&repo_path))
                .is_err();

            if !is_detached {
                ushell.run(cmd!("git reset --hard origin/{}", commitish).cwd(&repo_path))?;
            }

            get_absolute_path(ushell, &repo_path)?
        }

        KernelSrc::Tar { tarball_path } => {
            ushell.run(cmd!("tar xvf {}", tarball_path))?;

            get_absolute_path(
                ushell,
                tarball_path
                    .trim_end_matches(".tar.gz")
                    .trim_end_matches(".tar.xz")
                    .trim_end_matches(".tgz"),
            )?
        }
    };

    // kbuild path.
    let kbuild_path = &format!("{}/kbuild", source_path);

    ushell.run(cmd!("mkdir -p {}", kbuild_path))?;

    // save old config if there is one.
    ushell.run(cmd!("cp .config config.bak").cwd(kbuild_path).allow_error())?;

    // configure the new kernel we are about to build.
    ushell.run(cmd!("make O={} defconfig", kbuild_path).cwd(&source_path))?;

    match config.base_config {
        // Nothing else to do
        KernelBaseConfigSource::Defconfig => {}

        KernelBaseConfigSource::Current => {
            let config = ushell
                .run(cmd!("ls -1 /boot/config-* | head -n1").use_bash())?
                .stdout;
            let config = config.trim();
            ushell.run(cmd!("cp {} {}/.config", config, kbuild_path))?;
            ushell.run(cmd!("yes '' | make oldconfig").use_bash().cwd(kbuild_path))?;
        }

        KernelBaseConfigSource::Path(template_path) => {
            ushell.run(cmd!("cp {} {}/.config", template_path, kbuild_path))?;
            ushell.run(cmd!("yes '' | make oldconfig").use_bash().cwd(kbuild_path))?;
        }
    }

    for (opt, set) in config.extra_options.iter() {
        if *set {
            ushell.run(cmd!(
                "sed -i 's/# {} is not set/{}=y/' {}/.config",
                opt,
                opt,
                kbuild_path
            ))?;
        } else {
            ushell.run(cmd!(
                "sed -i '/{}=/s/{}=.*$/# {} is not set/' {}/.config",
                opt,
                opt,
                opt,
                kbuild_path
            ))?;
        }
    }

    // Make sure config is consistent
    ushell.run(cmd!("yes '' | make oldconfig").cwd(&kbuild_path))?;

    // Compile with as many processors as we have.
    //
    // NOTE: for some reason, this sometimes fails the first time, so just do it again.
    //
    // NOTE: we pipe `yes` into make because in some cases the build will request updating some
    // aspects of the config in ways that `make oldconfig` does not address, such as to generate a
    // signing key.
    let nprocess = get_num_cores(ushell)?;

    let make_target = match pkg_type {
        KernelPkgType::Deb => "bindeb-pkg",
        KernelPkgType::Rpm => "binrpm-pkg",
    };

    // Sometimes there is an error the first time. If so, retrying usually works.
    let res = ushell.run(
        cmd!(
            "yes '' | make -j {} CC=/usr/bin/gcc {} {}",
            nprocess,
            make_target,
            if let Some(kernel_local_version) = kernel_local_version {
                let kernel_local_version = kernel_local_version.replace("/", "-");
                format!("LOCALVERSION=-{}", kernel_local_version)
            } else {
                "".into()
            }
        )
        .cwd(kbuild_path),
    );
    if let Err(..) = res {
        ushell.run(
            cmd!(
                "make -j {}  CC=/usr/bin/gcc {} {}",
                nprocess,
                make_target,
                if let Some(kernel_local_version) = kernel_local_version {
                    let kernel_local_version = kernel_local_version.replace("/", "-");
                    format!("LOCALVERSION=-{}", kernel_local_version)
                } else {
                    "".into()
                }
            )
            .cwd(kbuild_path),
        )?;
    }

    // Build and install `cpupower` and `libcpupower`, if needed.
    if cpupower {
        ushell.run(
            cmd!("make -j {} && sudo make install", nprocess)
                .cwd(&dir!(source_path, "tools/power/cpupower/")),
        )?;
    }

    Ok(())
}

/// Something that may be done to a service.
pub enum ServiceAction {
    /// Start the service if it is not active. Otherwise, do nothing.
    Start,
    /// Stop the service if it is active. Otherwise, do nothing.
    Stop,
    /// Restart the service, or start it if it is not active. Requires that the service exist.
    Restart,
    /// Disable and stop the service if it is active. Otherwise, do nothing.
    Disable,
    /// Enable the service, but do not start it. Requires that the service exist.
    Enable,
}

/// Start, stop, enable, disable, or restart a service.
pub fn service(
    shell: &SshShell,
    service: &str,
    action: ServiceAction,
) -> Result<(), failure::Error> {
    let is_active = service_is_active(shell, service)?;

    match action {
        ServiceAction::Restart => {
            if is_active {
                shell.run(cmd!("sudo systemctl restart {}", service))?;
            } else {
                shell.run(cmd!("sudo systemctl start {}", service))?;
            }
        }
        ServiceAction::Start => {
            if !is_active {
                shell.run(cmd!("sudo systemctl start {}", service))?;
            }
        }
        ServiceAction::Stop => {
            if is_active {
                shell.run(cmd!("sudo systemctl stop {}", service))?;
            }
        }
        ServiceAction::Enable => {
            shell.run(cmd!("sudo systemctl enable {}", service))?;
        }
        ServiceAction::Disable => {
            if is_active {
                shell.run(cmd!("sudo systemctl disable --now {}", service))?;
            }
        }
    }

    Ok(())
}

/// Returns true if the given service is running.
pub fn service_is_active(shell: &SshShell, service: &str) -> Result<bool, failure::Error> {
    Ok(shell.run(cmd!("systemctl is-active {}", service)).is_ok())
}

/// Set up passphraseless SSH to localhost.
pub fn setup_passphraseless_local_ssh(ushell: &SshShell) -> Result<(), failure::Error> {
    // First check if it already works
    if ushell
        .run(cmd!("ssh -o StrictHostKeyChecking=no localhost -- whoami"))
        .is_err()
    {
        with_shell! { ushell =>
            cmd!("ssh-keygen -t rsa -N '' -f ~/.ssh/id_rsa").no_pty(),
            cmd!("cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys"),
            cmd!("ssh-keygen -R localhost -f ~/.ssh/known_hosts"),
            cmd!("ssh-keyscan -H localhost >> ~/.ssh/known_hosts"),
        }
    }

    // Test it.
    ushell.run(cmd!("ssh localhost -- whoami"))?;

    Ok(())
}

/// Returns the device id from `/dev/disk/by-id/` of the given device. `dev_name` should _exclude_
/// the `/dev/` (e.g. `sda`).
pub fn get_device_id(shell: &SshShell, dev_name: &str) -> Result<String, failure::Error> {
    let out = shell.run(
        cmd!(
            r#"ls -lah /dev/disk/by-id/ | \
            sort -k 11 | \
            awk '{{print $11 "\t" $9}}' | \
            grep {} | \
            head -n 1 | \
            awk '{{print $2}}'"#,
            dev_name
        )
        .use_bash(),
    )?;
    let name = out.stdout.trim().to_owned();

    if name.is_empty() {
        Err(failure::format_err!(
            "Unable to find device by ID: {}",
            dev_name
        ))
    } else {
        Ok(name)
    }
}

/// Resize the root partition and file system to take up the whole remainder of the drive,
/// destroying an partitions that come after it.
pub fn resize_root_partition(shell: &SshShell) -> Result<(), failure::Error> {
    // Find the root partition and device name.
    let output = shell
        .run(cmd!(
            r#"eval `lsblk -P -o NAME,PKNAME,MOUNTPOINT |\
              grep 'MOUNTPOINT="/"'` ; echo $NAME ; echo $PKNAME"#
        ))?
        .stdout;
    let mut output = output.split_whitespace();
    let root_part = output.next().unwrap().trim().to_owned();
    let root_device = output.next().unwrap().trim().to_owned();

    // Dump the original partition table.
    shell.run(cmd!(
        "sudo sfdisk -d /dev/{} | tee /tmp/sfdisk.old",
        root_device
    ))?;
    shell.run(cmd!("cp /tmp/sfdisk.old /tmp/sfdisk.new"))?;

    // Disable swap partitions.
    shell.run(cmd!(
        "for part in `lsblk -l | grep 'SWAP' | \
         grep {} | awk '{{print $1}}'` ; do \
         sudo swapoff /dev/$part ; done",
        root_device
    ))?;

    // Compute a new partition table. We want to canabalize all partitions after the root
    // partition.
    let table_raw = shell
        .run(cmd!(
            r#"cat /tmp/sfdisk.new |\
               grep '^/dev' |\
               sed 's|/dev/\([a-z0-9]*\).*start= *\([0-9]*\).*size= *\([0-9]*\).*|\1 \2 \3|g'"#,
        ))?
        .stdout;
    let mut old_partitions = std::collections::HashMap::new();
    for line in table_raw.lines() {
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap().trim();
        let start = parts.next().unwrap().trim().parse::<usize>().unwrap();
        let size = parts.next().unwrap().trim().parse::<usize>().unwrap();

        old_partitions.insert(name, (start, size));
    }

    // Compute the list of partitions to delete and the new size of the root partition.
    let root_start = old_partitions.get(root_part.as_str()).unwrap().0;
    let to_delete: Vec<_> = old_partitions
        .iter()
        .filter_map(|(name, (start, _))| {
            if *start > root_start {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    let root_new_size: usize = to_delete
        .iter()
        .map(|part| old_partitions.get(*part).unwrap().1)
        .sum();

    // Delete the partitions we want to get rid of (but not actually yet).
    for part in to_delete.into_iter() {
        shell.run(cmd!(r#"sed -i "/{}/d" /tmp/sfdisk.new"#, part))?;
    }

    // Update the root partition size (but not actually yet).
    shell.run(cmd!(
        r#"sed "s|\(.*{}.*size= *\)[0-9]*\(.*\)|\1{}\2|" /tmp/sfdisk.new > /tmp/sfdisk.new1 \
        && mv /tmp/sfdisk.new1 /tmp/sfdisk.new"#,
        root_part,
        root_new_size
    ))?;

    // Print old and new partition tables.
    shell.run(cmd!("cat /tmp/sfdisk.old /tmp/sfdisk.new"))?;

    // Actually change disk layout now.
    shell.run(cmd!("sudo sfdisk --force /dev/{} < /tmp/sfdisk.new", root_device).allow_error())?;
    shell.run(cmd!("sudo partprobe /dev/{}", root_device))?;
    shell.run(cmd!("sudo resize2fs /dev/{}", root_part))?;

    // Finally print results.
    shell.run(cmd!("lsblk ; df -h"))?;

    Ok(())
}

/// Dump a bunch of kernel info for debugging.
pub fn dump_sys_info(shell: &SshShell) -> Result<(), failure::Error> {
    with_shell! { shell =>
        cmd!("uname -a"),
        cmd!("lsblk"),
        cmd!("free -h"),
    }

    Ok(())
}

/// Set the kernel `printk` level that gets logged to `dmesg`. `0` is only high-priority
/// messages. `7` is all messages.
pub fn set_kernel_printk_level(shell: &SshShell, level: usize) -> Result<(), failure::Error> {
    assert!(level <= 7);
    shell.run(cmd!("echo {} | sudo tee /proc/sys/kernel/printk", level).use_bash())?;
    Ok(())
}

/// Tell the OOM killer not to kill the given process.
pub fn oomkiller_blacklist_by_name(shell: &SshShell, name: &str) -> Result<(), failure::Error> {
    shell.run(cmd!(
        r"pgrep -f {} | while read PID; do \
            echo -1000 | sudo tee /proc/$PID/oom_score_adj;
        done",
        name
    ))?;

    Ok(())
}

/// Turn off soft lockup and NMI watchdogs if possible in the shell.
pub fn turn_off_watchdogs(shell: &SshShell) -> Result<(), failure::Error> {
    shell.run(cmd!(
        "echo 0 | sudo tee /proc/sys/kernel/hung_task_timeout_secs"
    ))?;
    shell.run(cmd!("echo 0 | sudo tee /proc/sys/kernel/watchdog").allow_error())?;
    Ok(())
}

/// Gathers some common stats for any experiment. This is intended to be called after the
/// simulation.
///
/// `out_file` should be just the file name, not the directory path. This function will cause the
/// output to be in the standard locations.
///
/// Requires `sudo`.
pub fn gen_standard_host_output(out_file: &str, shell: &SshShell) -> Result<(), failure::Error> {
    let out_file = dir!(setup00000::HOSTNAME_SHARED_RESULTS_DIR, out_file);

    // Host config
    shell.run(cmd!("echo -e 'Host Config\n=====' > {}", out_file))?;
    shell.run(cmd!("cat /proc/cpuinfo >> {}", out_file))?;
    shell.run(cmd!("lsblk >> {}", out_file))?;

    // Memory usage, compressibility
    shell.run(cmd!(
        "echo -e '\nSimulation Stats (Host)\n=====' >> {}",
        out_file
    ))?;
    shell.run(cmd!("cat /proc/meminfo >> {}", out_file))?;
    shell.run(cmd!(
        "sudo bash -c 'tail /sys/kernel/debug/zswap/*' >> {}",
        out_file
    ))?;
    shell.run(cmd!(
        "(tail /proc/zerosim_guest_offset; echo) >> {}",
        out_file
    ))?;

    // Kernel log
    shell.run(cmd!("echo -e '\ndmesg (Host)\n=====' >> {}", out_file))?;
    shell.run(cmd!("dmesg >> {}", out_file))?;

    // Sync
    shell.run(cmd!("sync"))?;

    Ok(())
}

/// On Broadwell or older, the `*.walk_duration` perf counters are used to measure the amount of
/// cycles spent in page walks. On processors after Broadwell, the name of the counter is
/// `*.walk_active`.
///
/// This function checks which it is and returns either `Ok("walk_duration")` or
/// `Ok("walk_active")`.
pub fn page_walk_perf_counter_suffix(shell: &SshShell) -> Result<String, failure::Error> {
    let output = shell
        .run(cmd!(
            "(sudo perf list | grep -o walk_active > /tmp/x && cat /tmp/x | uniq) || echo walk_duration"
        ))?
        .stdout;

    Ok(output.trim().to_owned())
}
