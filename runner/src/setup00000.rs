//! Setup the given cloudlab node for vagrant via libvirt and install a custom kernel from source.
//! This does not set up the guest -- only the host. It allows formatting and setting up a device
//! as the home directory of the given user. It also allows choosing the git branch to compile the
//! kernel from.

use std::process::Command;

use spurs::{
    cmd,
    ssh::{Execute, SshShell},
};

use crate::common::{
    get_user_home_dir, setup00000::CLOUDLAB_SHARED_RESULTS_DIR, KernelPkgType, Login,
    RESEARCH_WORKSPACE_PATH, VAGRANT_SUBDIRECTORY, ZEROSIM_EXPERIMENTS_SUBMODULE,
    ZEROSIM_KERNEL_SUBMODULE,
};

const VAGRANT_RPM_URL: &str =
    "https://releases.hashicorp.com/vagrant/2.1.5/vagrant_2.1.5_x86_64.rpm";

/// Location of `.ssh` directory on UW CS AFS so we can install it on experimental machines.
const SSH_LOCATION: &str = "/u/m/a/markm/.ssh";

pub fn run<A>(
    dry_run: bool,
    login: &Login<A>,
    device: Option<&str>,
    git_branch: Option<&str>,
    only_vm: bool,
    token: &str,
    swap_devs: Vec<&str>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug,
{
    // Connect to the remote
    let mut ushell = SshShell::with_default_key(login.username.as_str(), &login.host)?;
    if dry_run {
        ushell.toggle_dry_run();
    }

    let user_home = &get_user_home_dir(&ushell)?;

    if !only_vm {
        // Rename `poweroff` so we can't accidentally use it
        if let Ok(res) = ushell.run(
            cmd!("PATH='/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin':$PATH type poweroff")
                .use_bash(),
        ) {
            ushell.run(
                cmd!(
                    "sudo mv $(echo '{}' | awk '{{print $3}}') /usr/sbin/poweroff-actually",
                    res.stdout.trim()
                )
                .use_bash(),
            )?;
        }

        // Install a bunch of stuff
        ushell.run(cmd!("sudo yum group install -y 'Development Tools'"))?;
        ushell.run(spurs::centos::yum_install(&[
            "bc",
            "openssl-devel",
            "libvirt",
            "libvirt-devel",
            "qemu-kvm",
            "virt-manager",
            "pciutils-devel",
            "bash-completion",
            "elfutils-devel",
            "libunwind-devel",
            "audit-libs-devel",
            "slang-devel",
            "perl-ExtUtils-Embed",
            "binutils-devel",
            "xz-devel",
            "numactl-devel",
        ]))?;
        ushell.run(spurs::util::add_to_group("libvirt"))?;

        let installed = ushell
            .run(cmd!("yum list installed vagrant | grep -q vagrant"))
            .is_ok();

        if !installed {
            ushell.run(cmd!("sudo yum -y install {}", VAGRANT_RPM_URL))?;
        }

        ushell.run(cmd!("vagrant plugin install vagrant-libvirt"))?;

        // Need a new shell so that we get the new user group
        let mut ushell = SshShell::with_default_key(login.username.as_str(), &login.host)?;
        if dry_run {
            ushell.toggle_dry_run();
        }

        if let Some(device) = device {
            // Set up home device/directory
            // - format the device and create a partition
            // - mkfs on the partition
            // - copy data to new partition and mount as home dir
            ushell.run(spurs::util::write_gpt(device))?;
            ushell.run(spurs::util::create_partition(device))?;
            spurs::util::format_partition_as_ext4(
                &ushell,
                dry_run,
                &format!("{}1", device), // assume it is the first device partition
                user_home,
                login.username.as_str(),
            )?;
        }

        // Setup swap devices, and leave a research-settings.json file. If no swap devices were
        // specififed, use all unpartitioned, unmounted devices.
        if swap_devs.is_empty() {
            let unpartitioned = spurs::util::get_unpartitioned_devs(&ushell, dry_run)?;
            for dev in unpartitioned.iter() {
                ushell.run(cmd!("sudo mkswap /dev/{}", dev))?;
            }
        } else {
            for dev in swap_devs.iter() {
                ushell.run(cmd!("sudo mkswap /dev/{}", dev))?;
            }

            crate::common::set_remote_research_setting(&ushell, "swap-devices", &swap_devs)?;
        }

        // clone the research workspace and build/install the 0sim kernel.
        if let Some(git_branch) = git_branch {
            const CONFIG_SET: &[(&str, bool)] = &[
                // turn on 0sim
                ("CONFIG_ZSWAP", true),
                ("CONFIG_ZPOOL", true),
                ("CONFIG_ZBUD", true),
                ("CONFIG_ZTIER", true),
                ("CONFIG_SBALLOC", true),
                ("CONFIG_ZSMALLOC", true),
                ("CONFIG_X86_TSC_OFFSET_HOST_ELAPSED", true),
                ("CONFIG_SSDSWAP", true),
                // disable spectre/meltdown mitigations
                ("CONFIG_PAGE_TABLE_ISOLATION", false),
                ("CONFIG_RETPOLINE", false),
                // for `perf` stack traces
                ("CONFIG_FRAME_POINTER", true),
            ];

            const SUBMODULES: &[&str] = &[ZEROSIM_KERNEL_SUBMODULE, ZEROSIM_EXPERIMENTS_SUBMODULE];

            let kernel_path = format!(
                "{}/{}/{}",
                user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_KERNEL_SUBMODULE
            );

            let git_hash = crate::common::clone_research_workspace(&ushell, token, SUBMODULES)?;

            crate::common::build_kernel(
                dry_run,
                &ushell,
                &kernel_path,
                git_branch,
                CONFIG_SET,
                &format!("{}-{}", git_branch.replace("_", "-"), git_hash),
                KernelPkgType::Rpm,
            )?;

            // Build cpupower
            ushell.run(
                cmd!("make")
                    .cwd(&format!("{}/tools/power/cpupower/", kernel_path))
                    .dry_run(dry_run),
            )?;

            // install linux-dev
            ushell.run(
                cmd!("sudo yum -y install `ls -t1 | head -n2 | sort`")
                    .use_bash()
                    .cwd(&format!("{}/rpmbuild/RPMS/x86_64/", user_home)),
            )?;

            // update grub to choose this entry (new kernel) by default
            ushell.run(cmd!("sudo grub2-set-default 0"))?;
        }

        ushell.run(cmd!("mkdir -p {}", CLOUDLAB_SHARED_RESULTS_DIR))?;

        // change image location
        ushell.run(cmd!("mkdir -p images/"))?;
        ushell.run(cmd!("chmod +x ."))?;
        ushell.run(cmd!("chmod +x images/"))?;
        ushell.run(cmd!("chown {}:qemu images/", login.username.as_str()))?;
        ushell.run(cmd!("sudo virsh pool-destroy default"))?;
        ushell.run(cmd!("sudo virsh pool-undefine default"))?;
        ushell.run(cmd!(
            "sudo virsh pool-define-as --name default --type dir --target {}/images/",
            user_home
        ))?;
        ushell.run(cmd!("sudo virsh pool-autostart default"))?;
        ushell.run(cmd!("sudo virsh pool-start default"))?;
        ushell.run(cmd!("sudo virsh pool-list"))?;

        spurs::util::reboot(&mut ushell, dry_run)?;
    }

    // Add ssh key to VM
    let vagrant_path = &format!("{}/{}", RESEARCH_WORKSPACE_PATH, VAGRANT_SUBDIRECTORY);

    crate::common::exp00000::gen_vagrantfile(&ushell, 20, 1)?;
    ushell.run(cmd!("vagrant halt").cwd(vagrant_path))?;
    ushell.run(cmd!("vagrant up").cwd(vagrant_path))?;

    let key = std::fs::read_to_string(format!("{}/{}", SSH_LOCATION, "id_rsa.pub"))?;
    let key = key.trim();
    ushell.run(
        cmd!(
            "vagrant ssh -- 'echo {} >> /home/vagrant/.ssh/authorized_keys'",
            key
        )
        .cwd(vagrant_path),
    )?;
    ushell.run(cmd!("vagrant ssh -- sudo cp -r /home/vagrant/.ssh /root/").cwd(vagrant_path))?;

    // Old key will be cached for the VM, but it is likely to have changed
    let (host, _) = spurs::util::get_host_ip(&login.host);
    let _ = Command::new("ssh-keygen")
        .args(&[
            "-f",
            &format!("{}/{}", SSH_LOCATION, "known_hosts"),
            "-R",
            &format!("[{}]:{}", host, crate::common::exp00000::VAGRANT_PORT),
        ])
        .status()
        .unwrap();

    // Start vagrant
    let vrshell = crate::common::exp00000::start_vagrant(&ushell, &login.host, 20, 1)?;
    let vushell = crate::common::exp00000::connect_to_vagrant_user(&login.host)?;

    // Install stuff on the VM
    vrshell.run(spurs::centos::yum_install(&[
        "vim",
        "git",
        "memcached",
        "gcc",
        "libcgroup",
        "libcgroup-tools",
    ]))?;

    vrshell.run(
        cmd!(
            "curl https://sh.rustup.rs -sSf | \
             sh -s -- --default-toolchain nightly --no-modify-path -y"
        )
        .use_bash()
        .no_pty(),
    )?;
    vushell.run(
        cmd!(
            "curl https://sh.rustup.rs -sSf | \
             sh -s -- --default-toolchain nightly --no-modify-path -y"
        )
        .use_bash()
        .no_pty(),
    )?;
    ushell.run(
        cmd!(
            "curl https://sh.rustup.rs -sSf | \
             sh -s -- --default-toolchain nightly --no-modify-path -y"
        )
        .use_bash()
        .no_pty(),
    )?;

    // We share the research-workspace with the VM via a vagrant shared directory (NFS) so that
    // there is only one version used across both (less versioning to track). Now, just compile the
    // benchmarks and install rust on the host.

    // Install benchmarks.

    vushell.run(
        cmd!("/home/vagrant/.cargo/bin/cargo build --release").cwd(&format!(
            "/home/vagrant/{}/{}",
            RESEARCH_WORKSPACE_PATH, ZEROSIM_EXPERIMENTS_SUBMODULE
        )),
    )?;

    // Make sure the TSC is marked as a reliable clock source in the guest. We get the existing
    // kernel command line and replace it with the same + `tsc=reliable`.
    let current_cmd_line = vushell
        .run(
            cmd!(r#"cat /etc/default/grub | grep -oP 'GRUB_CMDLINE_LINUX="\K.+(?=")'"#).use_bash(),
        )?
        .stdout;
    let current_cmd_line = current_cmd_line
        .trim()
        .replace("/", r"\/")
        .replace(r"\", r"\\");

    vrshell.run(cmd!(
        "sed -i 's/{}/{} tsc=reliable/' /etc/default/grub",
        current_cmd_line,
        current_cmd_line
    ))?;
    vrshell.run(cmd!("grub2-mkconfig -o /boot/grub2/grub.cfg"))?;

    // Need to run shutdown to make sure that the next host reboot doesn't lose guest data.
    let _ = vrshell.run(cmd!("sudo poweroff")); // This will give a TCP error for obvious reasons

    Ok(())
}
