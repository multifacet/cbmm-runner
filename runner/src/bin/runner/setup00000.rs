//! Setup the given test node for vagrant via libvirt and install a custom kernel from source.
//! This does not set up the guest -- only the host. It allows formatting and setting up a device
//! as the home directory of the given user. It also allows choosing the git branch to compile the
//! kernel from.

use std::process::Command;

use clap::clap_app;

use failure::ResultExt;

use runner::{
    dir,
    downloads::{artifact_info, download, download_and_extract, Artifact},
    exp_0sim::*,
    get_user_home_dir,
    paths::{setup00000::*, *},
    with_shell, KernelBaseConfigSource, KernelConfig, KernelPkgType, KernelSrc, Login,
    ServiceAction,
};

use spurs::{cmd, Execute, SshShell};

pub fn cli_options() -> clap::App<'static, 'static> {
    clap_app! { setup00000 =>
        (about: "Sets up the given _centos_ test machine for use with vagrant. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")

        (@arg PROXY: +takes_value --proxy
         "(Optional) set up the VM to use the given proxy. Leave off the protocol \
         (e.g. squid.cs.wisc.edu:3128)")

        (@arg AWS: --aws
         "(Optional) Do AWS-specific stuff.")

        (@arg HOST_DEP: --host_dep
         "(Optional) If passed, install host dependencies")

        (@arg HOME_DEVICE: +takes_value --home_device
         "(Optional) the device to format and use as a home directory \
         (e.g. --home_device /dev/sda). The device should _not_ already be mounted.")

        (@arg MAPPER_DEVICE: +takes_value --mapper_device conflicts_with[SWAP_DEVS]
         "(Optional) the device to use with device mapper as a thinly-provisioned \
         swap space (e.g. --mapper_device /dev/sda). The device should _not_ already be mounted.")
        (@arg SWAP_DEVS: +takes_value --swap ... conflicts_with[MAPPER_DEVICE]
         "(Optional) specify which devices to use as swap devices. The devices must \
          all be _unmounted_. By default all unpartitioned, unmounted devices are used \
          (e.g. --swap sda sdb sdc).")

        (@arg UNSTABLE_DEVICE_NAMES: --unstable_device_names
         "(Optional) specifies that device names may change across a reboot \
          (e.g. /dev/sda might be /dev/sdb after a reboot). In this case, the device \
          names used in other arguments will be converted to stable names based on device ids."
        )

        (@arg CLONE_WKSPC: --clone_wkspc
         "(Optional) If passed, clone the workspace on the remote (or update if already cloned \
         using the git access method in src/lib.rs. If the method uses HTTPS to access a \
         private repository, the --secret option must also be passed giving the GitHub personal \
         access token or password.")

        (@arg SECRET: +takes_value --secret
         "(Optional) If we should clone the workspace, this is the Github personal access \
          token or password for cloning the repo.")

        (@arg FIREWALL: --firewall
         "(Optional) Set up firewall rules properly.")

        (@arg HOST_KERNEL: +takes_value --host_kernel
         "(Optional) The git branch to compile the kernel from (e.g. --host_kernel master)")

        (@arg HOST_BMKS: --host_bmks
         "(Optional) If passed, build host benchmarks. This also makes them available to the guest.")

        (@arg HOST_PREP: --prepare_host
         "(Optional) Prepare the host for initializing the VM.")

        (@arg DISABLE_EPT: --disable_ept
         "(Optional) may need to disable Intel EPT on machines that don't have enough physical bits.")
        (@arg DESTROY_EXISTING: --DESTROY_EXISTING
         "(Optional) Destroy any existing VM")
        (@arg CREATE_VM: --create_vm
         "(Optional) Create and initialize a new VM")

        (@arg GUEST_KERNEL: --guest_kernel
         "(Optional) Build and install a guest kernel")

        (@arg GUEST_BMKS: --guest_bmks
         "(Optional) Build and install a guest benchmarks")
        (@arg HADOOP: --hadoop
         "(Optional) set up hadoop stack on VM.")

        (@arg CENTOS7: --centos7
         "(Optional) the remote machine is running CentOS 7.")
    }
}

struct SetupConfig<'a, A>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    /// Login credentials for the host.
    login: Login<'a, 'a, A>,

    /// Do AWS-specific stuff.
    aws: bool,

    /// Setup the host and guest to work behind the given proxy.
    setup_proxy: Option<&'a str>,

    /// Install host dependencies, rename poweorff.
    host_dep: bool,

    /// Set the device to be used as the home device.
    home_device: Option<&'a str>,
    /// Set the device to be used with device mapper.
    mapper_device: Option<&'a str>,
    /// Set the devices to be used
    swap_devices: Option<Vec<&'a str>>,
    /// Device names are unstable and should be converted to UUIDs.
    unstable_names: bool,

    /// Should we clone/update the workspace?
    clone_wkspc: bool,
    /// The PAT or password to clone/update the workspace with, if needed.
    secret: Option<&'a str>,

    /// Should we set up firewall rules? This is needed for the guest to be able to properly
    /// connect to the host, the internet, etc.
    firewall: bool,

    /// The git branch/hash/tag to compile the kernel from (e.g. master or v4.10).
    commitish: Option<&'a str>,

    /// Should we build host benchmarks?
    host_bmks: bool,

    /// Should we prepare the host for initing the VM? This needs to be done only once?
    host_prep: bool,

    /// Disable EPT on the host.
    disable_ept: bool,
    /// Destroy any existing VM.
    destroy_existing_vm: bool,
    /// Create and init a new VM, including installing guest dependencies.
    create_vm: bool,

    /// Compile and install a recent Linux on the guest.
    guest_kernel: bool,

    /// Compile and install guest bmks.
    guest_bmks: bool,
    /// Set up the Hadoop on the guest.
    setup_hadoop: bool,

    /// The remote machine is using Centos 7, rather thena Centos 8.
    centos7: bool,
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let aws = sub_m.is_present("AWS");

    let setup_proxy = sub_m.value_of("PROXY");

    let host_dep = sub_m.is_present("HOST_DEP");

    let home_device = sub_m.value_of("HOME_DEVICE");
    let mapper_device = sub_m.value_of("MAPPER_DEVICE");
    let swap_devices = sub_m.values_of("SWAP_DEVS").map(|i| i.collect());
    let unstable_names = sub_m.is_present("UNSTABLE_DEVICE_NAMES");

    let clone_wkspc = sub_m.is_present("CLONE_WKSPC");
    let secret = sub_m.value_of("SECRET");

    let firewall = sub_m.is_present("FIREWALL");

    let commitish = sub_m.value_of("HOST_KERNEL");

    let host_bmks = sub_m.is_present("HOST_BMKS");

    let host_prep = sub_m.is_present("HOST_PREP");

    let disable_ept = sub_m.is_present("DISABLE_EPT");
    let destroy_existing_vm = sub_m.is_present("DESTROY_EXISTING");
    let create_vm = sub_m.is_present("CREATE_VM");

    let guest_kernel = sub_m.is_present("GUEST_KERNEL");

    let setup_hadoop = sub_m.is_present("HADOOP");

    let guest_bmks = sub_m.is_present("GUEST_BMKS");

    let centos7 = sub_m.is_present("CENTOS7");

    let cfg = SetupConfig {
        login,
        aws,
        setup_proxy,
        host_dep,
        home_device,
        mapper_device,
        swap_devices,
        unstable_names,
        firewall,
        commitish,
        clone_wkspc,
        secret,
        host_bmks,
        host_prep,
        disable_ept,
        destroy_existing_vm,
        create_vm,
        guest_kernel,
        guest_bmks,
        setup_hadoop,
        centos7,
    };

    validate_options(&cfg)?;

    run_inner(cfg)
}

/// Check that the set of flags passed satisfies dependencies and is non-contradictory.
fn validate_options<A>(cfg: &SetupConfig<'_, A>) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    assert!(cfg.mapper_device.is_none() || cfg.swap_devices.is_none());

    Ok(())
}

/// Drives the actual setup, calling the other routines in this file.
fn run_inner<A>(cfg: SetupConfig<'_, A>) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Connect to the remote
    let mut ushell = SshShell::with_default_key(cfg.login.username, &cfg.login.host)?;

    // Set up the host
    if cfg.host_dep {
        rename_poweroff(&ushell)?;
        install_host_dependencies(&mut ushell, &cfg)?;
    }
    set_up_host_devices(&ushell, &cfg)?;
    set_up_host_iptables(&ushell, &cfg)?;
    clone_research_workspace(&ushell, &cfg)?;
    install_host_kernel(&ushell, &cfg)?;

    // disable Intel EPT if needed
    if cfg.disable_ept {
        disable_ept(&ushell)?;
    }

    if cfg.host_dep {
        install_rust(&ushell)?;
    }
    if cfg.host_bmks {
        build_host_benchmarks(&ushell, &cfg)?;
    }

    // Prepare to install VM
    if cfg.host_prep {
        prepare_host_for_vm_and_reboot(&mut ushell, &cfg)?;
    }

    if cfg.destroy_existing_vm {
        destroy_vm(&ushell)?;
    }

    let (vrshell, vushell) = if cfg.create_vm {
        // Create the VM and install dependencies for the benchmarks/simulator.
        init_vm(&mut ushell, &cfg)?
    } else if cfg.guest_kernel || cfg.setup_hadoop || cfg.guest_bmks {
        // Start vagrant (that already exists)
        let vrshell = start_vagrant(
            &ushell,
            &cfg.login.host,
            20,
            1,
            /* fast */ true,
            ZEROSIM_SKIP_HALT,
            ZEROSIM_LAPIC_ADJUST,
        )?;
        let vushell = connect_to_vagrant_as_user(&cfg.login.host)?;

        (vrshell, vushell)
    } else {
        // Nothing left to do
        return Ok(());
    };

    // Setup of proxying if needed.
    let (vrshell, vushell) = if let Some(proxy) = cfg.setup_proxy {
        setup_proxy(vrshell, vushell, proxy, &cfg)?
    } else {
        (vrshell, vushell)
    };

    // Disable TSC offsetting for performance
    ZeroSim::tsc_offsetting(&ushell, false)?;

    install_guest_dependencies(&vrshell, &vushell, &cfg)?;

    if cfg.guest_kernel {
        install_guest_kernel(&ushell, &vrshell, &vushell)?;
    }

    // Install benchmarks.
    if cfg.guest_bmks || cfg.setup_hadoop {
        install_guest_benchmarks(&ushell, &vushell, &vrshell, &cfg)?;
    }

    // Make sure the TSC is marked as a reliable clock source in the guest.
    set_kernel_boot_param(&vrshell, "tsc", Some("reliable"))?;

    // Need to run shutdown to make sure that the next host reboot doesn't lose guest data.
    vrshell.run(cmd!("sync"))?;
    ushell.run(cmd!("sync"))?;
    let _ = vrshell.run(cmd!("sudo poweroff")); // This will give a TCP error for obvious reasons

    Ok(())
}

/// Rename `poweroff` to `poweroff-actually` so that we cannot accidentally use it.
fn rename_poweroff(ushell: &SshShell) -> Result<(), failure::Error> {
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

    Ok(())
}

/// Install a bunch of dependencies, including libvirt, which requires re-login-ing.
fn install_host_dependencies<A>(
    ushell: &mut SshShell,
    cfg: &SetupConfig<'_, A>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Make sure we have sbin in path.
    if cfg.centos7 {
        ushell.run(cmd!(
            "echo 'export PATH=$PATH:/usr/sbin/' | \
             sudo tee /etc/profile.d/sbin.sh"
        ))?;
    }

    // Install a bunch of stuff
    ushell.run(cmd!("sudo yum group install -y 'Development Tools'"))?;

    if cfg.aws {
        // This installs the qemu-kvm package, which we don't want on machines where we will run VMs.
        ushell.run(spurs_util::centos::yum_install(&["libguestfs-tools-c"]))?;
    } else if cfg.centos7 {
        with_shell! { ushell =>
            spurs_util::centos::yum_install(&[
                "centos-release-scl", "libunwind-devel", "libfdt-devel"
            ]),

            spurs_util::centos::yum_install(&["devtoolset-7"]),

            // Set up SCL as the default
            cmd!("echo 'source /opt/rh/devtoolset-7/enable' | \
                  sudo tee /etc/profile.d/recent-compilers.sh"),

            // SCL cannibalizes sudo, but their version kinda sucks because it doesn't take
            // any flags. So restore the original functionality by moving SCL's sudo away.
            cmd!("sudo mv /opt/rh/devtoolset-7/root/usr/bin/sudo \
                  /opt/rh/devtoolset-7/root/usr/bin/scl-sudo || \
                  ls /opt/rh/devtoolset-7/root/usr/bin/scl-sudo"),
        }
    }

    with_shell! { ushell =>
        spurs_util::centos::yum_install(&[
            "vim",
            "git",
            "libxslt-devel",
            "libxml2-devel",
            "gcc",
            "gcc-gfortran",
            "gcc-c++",
            "ruby-devel",
            "bc",
            "openssl-devel",
            "libvirt",
            "libvirt-devel",
            "virt-manager",
            "pciutils-devel",
            "bash-completion",
            "elfutils-devel",
            "audit-libs-devel",
            "slang-devel",
            "perl-ExtUtils-Embed",
            "binutils-devel",
            "xz-devel",
            "numactl-devel",
            "lsof",
            "java-1.8.0-openjdk-devel",
            "scl-utils",
            "glib2-devel",
            "pixman-devel",
            "zlib-devel",
            "fuse-devel",
            "fuse",
            "memcached",
            "libcgroup",
            "libcgroup-tools",
            "redis",
            "perf", // for debugging
            "wget",
            "libevent",
            "libevent-devel",
            "automake",
            "rpmdevtools",
            "python3",
            "iptables-services",
        ]),

        // Add user to libvirt group after installing
        spurs_util::add_to_group("libvirt"),
    }

    // Set up maven
    let user_home = &get_user_home_dir(&ushell)?;
    download_and_extract(ushell, Artifact::Maven, user_home, Some("maven"))?;
    ushell.run(cmd!(
        "echo -e 'export JAVA_HOME=/usr/lib/jvm/java/\n\
         export M2_HOME=~{}/maven/\n\
         export MAVEN_HOME=$M2_HOME\n\
         export PATH=${{M2_HOME}}/bin:${{PATH}}' | \
         sudo tee /etc/profile.d/java.sh",
        cfg.login.username
    ))?;

    if !cfg.centos7 {
        ushell.run(cmd!("sudo alternatives --set python /usr/bin/python3"))?;
    }

    let installed = ushell
        .run(cmd!("yum list installed vagrant | grep -q vagrant"))
        .is_ok();

    if !installed {
        let vagrant_info = artifact_info(Artifact::Vagrant);
        ushell.run(cmd!("sudo yum -y install {}", vagrant_info.url))?;
    }

    let installed = ushell
        .run(cmd!("vagrant plugin list | grep -q libvirt"))
        .is_ok();

    if !installed {
        if cfg.aws || !cfg.centos7 {
            // ruby-libvirt is finicky.
            ushell.run(cmd!(
                "CONFIGURE_ARGS='with-ldflags=-L/opt/vagrant/embedded/lib \
                 with-libvirt-include=/usr/include/libvirt with-libvirt-lib=/usr/lib' \
                 GEM_HOME=~/.vagrant.d/gems GEM_PATH=$GEM_HOME:/opt/vagrant/embedded/gems \
                 PATH=/opt/vagrant/embedded/bin:$PATH vagrant plugin install vagrant-libvirt",
            ))?;
        } else {
            ushell.run(cmd!("vagrant plugin install vagrant-libvirt"))?;
        }
    }

    // Need a new shell so that we get the new user group
    *ushell = SshShell::with_default_key(cfg.login.username, &cfg.login.host)?;

    // Build and Install QEMU 4.0.0 from source
    let qemu_info = download_and_extract(ushell, Artifact::Qemu, user_home, None)?;
    let qemu_dir = qemu_info.name.trim_end_matches(".tar.xz");
    let ncores = runner::get_num_cores(&ushell)?;

    with_shell! { ushell in qemu_dir =>
        cmd!("./configure"),
        cmd!("make -j {}", ncores),
        cmd!("sudo make install"),
    }

    ushell.run(cmd!(
        "sudo chown qemu:kvm /usr/local/bin/qemu-system-x86_64"
    ))?;

    // Make sure libvirtd can run the qemu binary
    ushell.run(cmd!(
        r#"sudo sed -i 's/#security_driver = "selinux"/security_driver = "none"/' \
                        /etc/libvirt/qemu.conf"#
    ))?;

    // Make sure libvirtd can access kvm
    ushell.run(cmd!(
        r#"echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666"' |\
                               sudo tee /lib/udev/rules.d/99-kvm.rules"#
    ))?;

    runner::service(&ushell, "libvirtd", ServiceAction::Restart)?;

    Ok(())
}

fn set_up_host_devices<A>(ushell: &SshShell, cfg: &SetupConfig<'_, A>) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    use runner::get_device_id;

    let user_home = &get_user_home_dir(&ushell)?;

    if let Some(device) = cfg.home_device {
        // Set up home device/directory
        // - format the device and create a partition
        // - mkfs on the partition
        // - copy data to new partition and mount as home dir
        //
        // This already handles unstable names properly, so no need to bother here.
        ushell.run(spurs_util::write_gpt(device))?;
        ushell.run(spurs_util::create_partition(device))?;
        spurs_util::format_partition_as_ext4(
            ushell,
            /* dry_run */ false,
            &format!("{}1", device), // assume it is the first device partition
            user_home,
            cfg.login.username,
        )?;
    }

    // Setup swap devices, and leave a research-settings.json file. If no swap devices were
    // specififed, use all unpartitioned, unmounted devices.
    if let Some(mapper_device) = cfg.mapper_device {
        // Setup a thinkly provisioned swap device

        const DM_META_FILE: &str = "dm.meta";

        // Convert name if needed
        let mapper_device = if cfg.unstable_names {
            let mapper_device_name_only = mapper_device.replace("/dev/", "");
            let dev_id = get_device_id(ushell, &mapper_device_name_only)?;
            dir!("/dev/disk/by-id/", dev_id)
        } else {
            mapper_device.into()
        };

        // create a 1GB zeroed file to be mounted as a loopback device for use as metadata dev for thin pool
        ushell.run(cmd!("sudo fallocate -z -l 1073741824 {}", DM_META_FILE))?;

        create_thin_swap(&ushell, DM_META_FILE, &mapper_device)?;

        // Save so that we can mount on reboot.
        runner::set_remote_research_setting(&ushell, "dm-meta", DM_META_FILE)?;
        runner::set_remote_research_setting(&ushell, "dm-data", mapper_device)?;
    } else if let Some(swap_devs) = &cfg.swap_devices {
        if swap_devs.is_empty() {
            let unpartitioned =
                spurs_util::get_unpartitioned_devs(ushell, /* dry_run */ false)?;
            for dev in unpartitioned.iter() {
                ushell.run(cmd!("sudo mkswap /dev/{}", dev))?;
            }
        } else {
            let mut swap_devices = Vec::new();
            for dev in swap_devs.iter() {
                let dev = if cfg.unstable_names {
                    let dev_id = get_device_id(ushell, dev)?;
                    dir!("disk/by-id/", dev_id)
                } else {
                    (*dev).to_owned()
                };

                ushell.run(cmd!("sudo mkswap /dev/{}", dev))?;

                swap_devices.push(dev);
            }

            runner::set_remote_research_setting(&ushell, "swap-devices", &swap_devices)?;
        }
    }

    Ok(())
}

fn set_up_host_iptables<A>(
    ushell: &SshShell,
    cfg: &SetupConfig<'_, A>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    if cfg.firewall {
        // disable firewalld, enable iptables services
        runner::service(ushell, "firewalld", ServiceAction::Disable)?;
        runner::service(ushell, "iptables", ServiceAction::Enable)?;

        with_shell! { ushell =>
            // set policy to ACCEPT so we won't get locked out!
            cmd!("sudo iptables -P INPUT ACCEPT"),

            // flush all rules
            cmd!("sudo iptables -F"),

            // allow loopback/local traffic
            cmd!("sudo iptables -A INPUT -i lo -p all -j ACCEPT"),
            cmd!("sudo iptables -A OUTPUT -o lo -p all -j ACCEPT"),

            // allow guest traffic
            cmd!("sudo iptables -A INPUT -i virbr1 -p all -j ACCEPT"),
            cmd!("sudo iptables -A OUTPUT -o virbr1 -p all -j ACCEPT"),

            // allow established/related traffic
            cmd!("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
            cmd!("sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT"),

            // allow ssh
            cmd!("sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"),
            cmd!("sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT"),

            // allow ssh to guest
            cmd!("sudo iptables -A INPUT -p tcp --dport 5555 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"),
            cmd!("sudo iptables -A OUTPUT -p tcp --sport 5555 -m conntrack --ctstate ESTABLISHED -j ACCEPT"),

            // allow rsync
            cmd!("sudo iptables -A INPUT -p tcp --dport 873 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"),
            cmd!("sudo iptables -A OUTPUT -p tcp --sport 873 -m conntrack --ctstate ESTABLISHED -j ACCEPT"),

            // reject all other traffic (and log for debugging)
            cmd!("sudo iptables -X LOGGING || true"),
            cmd!("sudo iptables -N LOGGING"),
            cmd!("sudo iptables -A INPUT -j LOGGING"),
            cmd!("sudo iptables -A LOGGING -m limit --limit 2/min -j LOG \
                 --log-prefix \"iptables-dropped: \" --log-level 4"),
            cmd!("sudo iptables -A LOGGING -j REJECT"),

            // print and save iptables
            cmd!("sudo iptables -L -v"),
            cmd!("sudo service iptables save"),
        };
    }

    Ok(())
}

fn clone_research_workspace<A>(
    ushell: &SshShell,
    cfg: &SetupConfig<'_, A>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    if cfg.clone_wkspc {
        const SUBMODULES: &[&str] = &[
            ZEROSIM_KERNEL_SUBMODULE,
            ZEROSIM_EXPERIMENTS_SUBMODULE,
            ZEROSIM_TRACE_SUBMODULE,
            ZEROSIM_HIBENCH_SUBMODULE,
            ZEROSIM_MEMHOG_SUBMODULE,
            ZEROSIM_METIS_SUBMODULE,
            ZEROSIM_MEMCACHED_SUBMODULE,
            ZEROSIM_NULLFS_SUBMODULE,
            ZEROSIM_MEMBUFFER_EXTRACT_SUBMODULE,
            ZEROSIM_ZLIB_SUBMODULE,
            ZEROSIM_YCSB_SUBMODULE,
        ];

        runner::clone_research_workspace(&ushell, cfg.secret, SUBMODULES)?;
    }

    Ok(())
}

fn install_host_kernel<A>(ushell: &SshShell, cfg: &SetupConfig<'_, A>) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    let user_home = &get_user_home_dir(&ushell)?;

    // clone the research workspace and build/install the 0sim kernel.
    if let Some(commitish) = cfg.commitish {
        let mut config_set = vec![
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
            // Compile with more recent kernels (bug workaround)
            ("CONFIG_NVM", true),
        ];

        // We don't have the keys to build with.
        if cfg.aws || !cfg.centos7 {
            config_set.push(("CONFIG_SYSTEM_TRUSTED_KEYS", false));
            config_set.push(("CONFIG_MODULE_SIG_KEY", false));
        }

        let kernel_path = dir!(
            user_home.as_str(),
            RESEARCH_WORKSPACE_PATH,
            ZEROSIM_KERNEL_SUBMODULE
        );

        let git_hash = runner::research_workspace_git_hash(ushell)?;

        runner::build_kernel(
            &ushell,
            KernelSrc::Git {
                repo_path: kernel_path.clone(),
                commitish: commitish.into(),
            },
            KernelConfig {
                base_config: KernelBaseConfigSource::Current,
                extra_options: &config_set,
            },
            Some(&runner::gen_local_version(commitish, &git_hash)),
            KernelPkgType::Rpm,
        )?;

        // Get name of RPM by looking for most recent file.
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

        ushell.run(
            cmd!(
                "sudo rpm -ivh --force {}/rpmbuild/RPMS/x86_64/{}",
                user_home,
                kernel_rpm
            )
            .use_bash(),
        )?;

        // update grub to choose this entry (new kernel) by default. This works as long as the new
        // kernel is the most recent one installed.
        ushell.run(cmd!("sudo grub2-set-default 0"))?;

        // Build cpupower
        ushell.run(cmd!("make").cwd(&format!("{}/tools/power/cpupower/", kernel_path)))?;
    }

    Ok(())
}

fn disable_ept(shell: &SshShell) -> Result<(), failure::Error> {
    shell.run(
        cmd!(
            r#"echo "options kvm-intel ept=0" | \
                           sudo tee /etc/modprobe.d/kvm-intel.conf"#
        )
        .use_bash(),
    )?;

    shell.run(cmd!("sudo rmmod kvm_intel"))?;
    shell.run(cmd!("sudo modprobe kvm_intel"))?;

    shell.run(cmd!("sudo tail /sys/module/kvm_intel/parameters/ept"))?;

    Ok(())
}

/// Install rust in the home directory of the given shell (can be guest or host).
fn install_rust(shell: &SshShell) -> Result<(), failure::Error> {
    shell.run(
        cmd!(
            "curl https://sh.rustup.rs -sSf | \
             sh -s -- --default-toolchain nightly --no-modify-path -y"
        )
        .use_bash()
        .no_pty(),
    )?;

    Ok(())
}

/// Build benchmarks on the host. This requires rust to be installed. Building the on the host also
/// makes them available to the guest, since they share the directory.
fn build_host_benchmarks<A>(
    ushell: &SshShell,
    _cfg: &SetupConfig<'_, A>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    let ncores = runner::get_num_cores(&ushell)?;

    // Build 0sim trace tool
    ushell.run(
        cmd!("$HOME/.cargo/bin/cargo build --release")
            .use_bash()
            .cwd(dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_TRACE_SUBMODULE)),
    )?;

    // Make the share directory (if it doesn't exist)
    ushell.run(cmd!("mkdir -p {}", HOSTNAME_SHARED_RESULTS_DIR))?;

    // 0sim-experiments
    ushell.run(cmd!("$HOME/.cargo/bin/cargo build --release").cwd(&dir!(
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    )))?;

    // NAS 3.4
    ushell.run(
        cmd!("tar xvf NPB3.4.tar.gz").cwd(&dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_BENCHMARKS_DIR)),
    )?;

    with_shell! { ushell
        in &dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_BENCHMARKS_DIR, "NPB3.4", "NPB3.4-OMP") =>

        cmd!("cp config/NAS.samples/make.def_gcc config/make.def"),
        cmd!(
            "sed -i 's/^FFLAGS.*$/FFLAGS  = -O3 -fopenmp \
             -m64 -fdefault-integer-8/' config/make.def"
        ),
    }

    ushell.run(cmd!("make clean cg CLASS=E").cwd(&dir!(
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_BENCHMARKS_DIR,
        "NPB3.4",
        "NPB3.4-OMP"
    )))?;
    ushell.run(cmd!("make clean cg CLASS=F").cwd(&dir!(
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_BENCHMARKS_DIR,
        "NPB3.4",
        "NPB3.4-OMP"
    )))?;

    // memhog
    ushell.run(
        cmd!("make -j {}", ncores).cwd(&dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_MEMHOG_SUBMODULE)),
    )?;

    // Metis
    with_shell! { ushell in &dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_METIS_SUBMODULE) =>
        cmd!("./configure"),
        cmd!("make -j {}", ncores),
    }

    // memcached
    with_shell! { ushell in &dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_MEMCACHED_SUBMODULE) =>
        cmd!("./autogen.sh"),
        cmd!("./configure"),
        cmd!("make -j {}", ncores),
    }

    // nullfs (for redis bgsave)
    with_shell! { ushell in &dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_NULLFS_SUBMODULE) =>
        cmd!("make -j {}", ncores),
    }

    // Eager paging scripts/programs
    ushell.run(cmd!("make -j {}", ncores).cwd(&dir!(
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_BENCHMARKS_DIR,
        ZEROSIM_SWAPNIL_PATH
    )))?;

    // Build zlib, membuffer-extract, and PinTool
    with_shell! { ushell in &dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_ZLIB_SUBMODULE) =>
        cmd!("./configure"),
        cmd!("make -j {}", ncores),
    }

    let membuffer_extract_dir = dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_MEMBUFFER_EXTRACT_SUBMODULE);
    download_and_extract(ushell, Artifact::Pin, &membuffer_extract_dir, Some("pin"))?;
    with_shell! { ushell in &membuffer_extract_dir =>
        cmd!("cp ../../{}/libz.a pin/source/tools/MemTrace", ZEROSIM_ZLIB_SUBMODULE),
        cmd!("cp membuffer.cpp pin/source/tools/MemTrace"),
        cmd!("cp membuffer.make pin/source/tools/MemTrace"),
        cmd!("echo -e '\ninclude membuffer.make' | tee -a pin/source/tools/MemTrace/makefile.rules"),
        cmd!("make -j {} -C pin/source/tools/MemTrace", ncores),

        cmd!("$HOME/.cargo/bin/cargo build --release")
            .use_bash(),
    }

    // Build kyoto cabinet
    let kc_dir = dir!(
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_YCSB_SUBMODULE,
        "kyotocabinet"
    );
    download_and_extract(ushell, Artifact::KyotoCabinetCore, &kc_dir, Some("kc-core"))?;
    with_shell! { ushell in &dir!(&kc_dir, "kc-core") =>
        cmd!("./configure --prefix=`pwd`"),
        cmd!("make -j {} && make install", ncores),
    }
    download_and_extract(ushell, Artifact::KyotoCabinetJava, &kc_dir, Some("kc-java"))?;
    with_shell! { ushell in &dir!(&kc_dir, "kc-java") =>
        cmd!("./configure --with-kc=../kc-core/"),
        cmd!("make -j {}", ncores),
    }

    // Build YCSB
    ushell.run(
        cmd!(
        "mvn -pl :memcached-binding -pl :redis-binding -pl :kyotocabinet-binding -am clean package"
    )
        .cwd(dir!(RESEARCH_WORKSPACE_PATH, ZEROSIM_YCSB_SUBMODULE)),
    )?;

    Ok(())
}

/// Prepare the host to install the VM. This involves rebooting the machine.
fn prepare_host_for_vm_and_reboot<A>(
    ushell: &mut SshShell,
    cfg: &SetupConfig<'_, A>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    let user_home = &get_user_home_dir(&ushell)?;

    // Configure libvirt to store images in the home directory.
    ushell.run(cmd!("mkdir -p images/"))?;
    ushell.run(cmd!("chmod +x ."))?;
    ushell.run(cmd!("chmod +x images/"))?;
    ushell.run(cmd!("sudo chown {}:qemu images/", cfg.login.username))?;

    runner::service(&ushell, "libvirtd", ServiceAction::Start)?;

    let def_exists = ushell
        .run(cmd!("sudo virsh pool-list --all | grep -q default"))
        .is_ok();
    if def_exists {
        ushell.run(cmd!("sudo virsh pool-destroy default"))?;
        ushell.run(cmd!("sudo virsh pool-undefine default"))?;
    }

    ushell.run(cmd!(
        "sudo virsh pool-define-as --name default --type dir --target {}/images/",
        user_home
    ))?;
    ushell.run(cmd!("sudo virsh pool-autostart default"))?;
    ushell.run(cmd!("sudo virsh pool-start default"))?;
    ushell.run(cmd!("sudo virsh pool-list"))?;

    // Reboot the host.
    spurs_util::reboot(ushell, /* dry_run */ false)?;

    // Disable TSC offsetting so that setup runs faster
    ZeroSim::tsc_offsetting(&ushell, false)?;

    // Make sure libvirtd is running.
    runner::service(&ushell, "libvirtd", ServiceAction::Restart)?;

    // Make sure NFS accepts UDP.
    ushell.run(cmd!(r"sed 's/\[nfsd\]/[nfsd]\nudp=y/' /etc/nfs.conf"))?;
    runner::service(&ushell, "nfs-server", ServiceAction::Restart)?;

    Ok(())
}

/// Destroys any existing VM forcibly.
fn destroy_vm(ushell: &SshShell) -> Result<(), failure::Error> {
    let vagrant_path = &dir!(RESEARCH_WORKSPACE_PATH, VAGRANT_SUBDIRECTORY);

    with_shell! { ushell in vagrant_path =>
        cmd!("vagrant halt --force || [ ! -e Vagrantfile ]").use_bash(),
        cmd!("sudo virsh net-undefine vagrant-libvirt || [ ! -e Vagrantfile ]").use_bash(),
        cmd!("vagrant destroy --force || [ ! -e Vagrantfile ]").use_bash(),
    }

    Ok(())
}

/// Create the VM and install dependencies for the benchmarks/simulator. Returns root and user
/// shells to the VM.
fn init_vm<A>(
    ushell: &mut SshShell,
    cfg: &SetupConfig<'_, A>,
) -> Result<(SshShell, SshShell), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Create the VM and add our ssh key to it.
    let vagrant_path = &dir!(RESEARCH_WORKSPACE_PATH, VAGRANT_SUBDIRECTORY);

    // Make the share directory (if it doesn't exist)
    ushell.run(cmd!("mkdir -p {}", HOSTNAME_SHARED_RESULTS_DIR))?;

    ushell.run(cmd!("cp Vagrantfile.bk Vagrantfile").cwd(vagrant_path))?;
    runner::gen_new_vagrantdomain(
        &ushell,
        if cfg.centos7 {
            VAGRANT_CENTOS7_BOX
        } else {
            VAGRANT_CENTOS8_BOX
        },
    )?;

    gen_vagrantfile(&ushell, 20, 1)?;

    // Make sure to turn off skip_halt and lapic_adjust
    ZeroSim::skip_halt(&ushell, false)?;
    ZeroSim::lapic_adjust(&ushell, false)?;

    ushell.run(cmd!("vagrant halt").cwd(vagrant_path))?;
    ushell.run(cmd!("vagrant up").cwd(vagrant_path))?; // This creates the VM

    let ssh_location = format!(
        "{}/.ssh",
        std::env::var("HOME").context("finding location of .ssh directory")?
    );

    let key = std::fs::read_to_string(dir!(&ssh_location, "id_rsa.pub"))?;
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
    let (host, _) = spurs_util::get_host_ip(&cfg.login.host);
    let _ = Command::new("ssh-keygen")
        .args(&[
            "-f",
            &dir!(&ssh_location, "known_hosts"),
            "-R",
            &format!("[{}]:{}", host, VAGRANT_PORT),
        ])
        .status()
        .unwrap();

    // Start vagrant
    let mut vrshell = start_vagrant(
        &ushell,
        &cfg.login.host,
        20,
        1,
        /* fast */ true,
        ZEROSIM_SKIP_HALT,
        ZEROSIM_LAPIC_ADJUST,
    )?;
    let mut vushell = connect_to_vagrant_as_user(&cfg.login.host)?;

    // Make sure we have an alternate way to get into the VM
    vrshell.run(cmd!("echo 0sim | passwd --stdin vagrant"))?;
    vrshell.run(cmd!("echo 0sim | passwd --stdin root"))?;

    // Sometimes on adsl, networking is kind of messed up until a host restart. Check for
    // connectivity, and try restarting.
    let pub_net = vushell.run(cmd!("ping -c 1 -W 10 1.1.1.1")).is_ok();
    if !pub_net {
        ushell.run(cmd!("vagrant halt").cwd(vagrant_path))?;
        spurs_util::reboot(ushell, /* dry_run */ false)?;

        vrshell = start_vagrant(
            &ushell,
            &cfg.login.host,
            20,
            1,
            /* fast */ true,
            ZEROSIM_SKIP_HALT,
            ZEROSIM_LAPIC_ADJUST,
        )?;
        vushell = connect_to_vagrant_as_user(&cfg.login.host)?;
    }

    // Keep tsc offsetting off (it may be turned on by start_vagrant).
    ZeroSim::tsc_offsetting(&ushell, false)?;

    Ok((vrshell, vushell))
}

/// Setup up proxying for the given root/user shells and proxy address:port. Consume the old shells
/// and return new shells with the proxy settings active.
fn setup_proxy<A>(
    rshell: SshShell,
    ushell: SshShell,
    proxy: &str,
    cfg: &SetupConfig<'_, A>,
) -> Result<(SshShell, SshShell), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    let mut parts = proxy.split(':');
    let address = parts.next().unwrap();
    let port = parts.next().unwrap();

    // user
    with_shell! { ushell =>
        cmd!("echo export http_proxy='{}' | tee --append .bashrc", proxy).use_bash(),
        cmd!("echo export https_proxy='{}' | tee --append .bashrc", proxy).use_bash(),
        cmd!("echo export HTTP_PROXY='{}' | tee --append .bashrc", proxy).use_bash(),
        cmd!("echo export HTTPS_PROXY='{}' | tee --append .bashrc", proxy).use_bash(),

        // Setup proxying for maven
        cmd!("mkdir -p .m2"),
        cmd!("cp {}/mvn-settings.xml .m2/settings.xml",
            dir!(
                RESEARCH_WORKSPACE_PATH,
                ZEROSIM_BENCHMARKS_DIR,
                ZEROSIM_HADOOP_PATH
            )
        ),
        cmd!("sed -i 's/PROXY_ADDRESS/{}/' .m2/settings.xml", address),
        cmd!("sed -i 's/PROXY_PORT/{}/' .m2/settings.xml", port),
    }

    // root
    with_shell! { rshell =>
        cmd!("echo export http_proxy='{}' | tee --append .bashrc", proxy).use_bash(),
        cmd!("echo export https_proxy='{}' | tee --append .bashrc", proxy).use_bash(),
        cmd!("echo export HTTP_PROXY='{}' | tee --append .bashrc", proxy).use_bash(),
        cmd!("echo export HTTPS_PROXY='{}' | tee --append .bashrc", proxy).use_bash(),
    }

    // proxy (https would be preferred, but RHEL/Centos 8 has issues with proxies)
    rshell.run(cmd!("echo proxy=http://{} | tee --append /etc/yum.conf", proxy).use_bash())?;

    // need to restart shell to get new env
    let rshell = connect_to_vagrant_as_root(&cfg.login.host)?;
    let ushell = connect_to_vagrant_as_user(&cfg.login.host)?;

    Ok((rshell, ushell))
}

fn install_guest_dependencies<A>(
    vrshell: &SshShell,
    vushell: &SshShell,
    cfg: &SetupConfig<'_, A>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Install stuff on the VM

    if cfg.centos7 {
        vrshell.run(spurs_util::centos::yum_install(&[
            "epel-release",
            "centos-release-scl",
        ]))?;
        vrshell.run(spurs_util::centos::yum_install(&["devtoolset-7"]))?;
        vrshell.run(cmd!(
            "echo 'source /opt/rh/devtoolset-7/enable' | \
             sudo tee /etc/profile.d/recent-compilers.sh"
        ))?;
        vrshell.run(cmd!(
            "sudo mv /opt/rh/devtoolset-7/root/usr/bin/sudo \
             /opt/rh/devtoolset-7/root/usr/bin/scl-sudo || \
             ls /opt/rh/devtoolset-7/root/usr/bin/scl-sudo"
        ))?;
    }

    vrshell.run(spurs_util::centos::yum_install(&[
        "vim",
        "git",
        "memcached",
        "gcc",
        "gcc-c++",
        "ggc-gfortran",
        "libcgroup",
        "libcgroup-tools",
        "java-1.8.0-openjdk-devel",
        "redis",
        "perf", // for debugging
        "libevent",
        "libevent-devel",
        "numactl-devel",
        "fuse-devel",
        "wget",
        "python3",
    ]))?;

    install_rust(vrshell)?;
    install_rust(vushell)?;

    // Set up maven
    let user_home = &get_user_home_dir(&vushell)?;
    download_and_extract(vushell, Artifact::Maven, user_home, Some("maven"))?;
    vushell.run(cmd!(
        "echo -e 'export JAVA_HOME=/usr/lib/jvm/java/\n\
         export M2_HOME=~vagrant/maven/\n\
         export MAVEN_HOME=$M2_HOME\n\
         export PATH=${{M2_HOME}}/bin:${{PATH}}' | \
         sudo tee /etc/profile.d/java.sh",
    ))?;

    Ok(())
}

/// Install a recent kernel on the guest.
///
/// We will compile on the host and copy the config and the RPM through the shared directory.
fn install_guest_kernel(
    ushell: &SshShell,
    vrshell: &SshShell,
    vushell: &SshShell,
) -> Result<(), failure::Error> {
    let user_home = &get_user_home_dir(&ushell)?;

    let guest_config = vushell
        .run(cmd!("ls -1 /boot/config-* | head -n1").use_bash())?
        .stdout;
    let guest_config = guest_config.trim();
    vushell.run(cmd!("cp {} {}", guest_config, VAGRANT_SHARED_DIR))?;

    let guest_config_base_name = std::path::Path::new(guest_config).file_name().unwrap();

    let kernel_info = download(ushell, Artifact::Linux, user_home, None)?;
    runner::build_kernel(
        &ushell,
        KernelSrc::Tar {
            tarball_path: kernel_info.name.into(),
        },
        KernelConfig {
            base_config: KernelBaseConfigSource::Path(dir!(
                HOSTNAME_SHARED_DIR,
                guest_config_base_name.to_str().unwrap()
            )),
            extra_options: &[
                // disable spectre/meltdown mitigations
                ("CONFIG_PAGE_TABLE_ISOLATION", false),
                ("CONFIG_RETPOLINE", false),
                // for `perf` stack traces
                ("CONFIG_FRAME_POINTER", true),
                // for bpf
                ("CONFIG_IKHEADERS", true),
                ("CONFIG_BPF", true),
                ("CONFIG_BPF_SYSCALL", true),
                ("CONFIG_BPF_JIT", true),
                ("CONFIG_HAVE_EBPF_JIT", true),
                ("CONFIG_BPF_EVENTS", true),
            ],
        },
        None,
        KernelPkgType::Rpm,
    )?;

    // Get name of RPM by looking for most recent file.
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

    ushell.run(
        cmd!(
            "cp {}/rpmbuild/RPMS/x86_64/{} {}/",
            user_home,
            kernel_rpm,
            dir!(user_home.as_str(), HOSTNAME_SHARED_DIR)
        )
        .use_bash(),
    )?;

    vrshell.run(cmd!(
        "rpm -ivh --force {}",
        dir!(VAGRANT_SHARED_DIR, kernel_rpm)
    ))?;

    vrshell.run(cmd!("sudo grub2-set-default 0"))?;

    Ok(())
}

/// Installation of benchmarks that must be done with a VM.
fn install_guest_benchmarks<A>(
    ushell: &SshShell,
    vushell: &SshShell,
    vrshell: &SshShell,
    cfg: &SetupConfig<'_, A>,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Hadoop/spark/hibench
    if cfg.setup_hadoop {
        vm_setup_hadoop(ushell, vushell, vrshell)?;
    }

    // Create a mountpoint for nullfs
    vushell.run(cmd!("sudo mkdir -p /mnt/nullfs"))?;
    vushell.run(cmd!("sudo chmod 777 /mnt/nullfs"))?;

    Ok(())
}

/// Set up hadoop and hibench in the guest.
fn vm_setup_hadoop(
    ushell: &SshShell,
    vushell: &SshShell,
    vrshell: &SshShell,
) -> Result<(), failure::Error> {
    let hadoop_path = dir!(
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_BENCHMARKS_DIR,
        ZEROSIM_HADOOP_PATH
    );

    runner::setup_passphraseless_local_ssh(vushell)?;

    // Add hadoop env vars to shell profile.
    let user_home = vushell.run(cmd!("echo $HOME"))?.stdout;
    let user_home = user_home.trim();
    vrshell.run(cmd!(
        "echo 'source {}/{}/hadoop_env.sh' >> ~/.bashrc",
        user_home,
        hadoop_path
    ))?;
    vushell.run(cmd!(
        "echo 'source {}/{}/hadoop_env.sh' >> ~/.bashrc",
        user_home,
        hadoop_path
    ))?;

    // Download and untar hadoop and spark.
    runner::hadoop::download_hadoop_tarball(&ushell, &hadoop_path)?;
    runner::hadoop::download_spark_tarball(&ushell, &hadoop_path)?;

    // Copy config options into place. These already have settings set, so we don't need to do a
    // lot of adjusting on the fly.
    with_shell! { ushell in &hadoop_path =>
        cmd!("cp hadoop-conf/* hadoop/etc/hadoop/"),
        cmd!("cp spark-conf/* spark/conf/"),
        cmd!("cp hibench-conf/* HiBench/conf/"),
    }

    // Do some setup for hadoop and then hibench
    vushell.run(
        cmd!("sh -x setup.sh")
            .use_bash()
            .cwd(&hadoop_path)
            .use_bash(),
    )?;

    Ok(())
}
