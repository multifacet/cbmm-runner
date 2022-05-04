//! Routines used for 0sim-related experiments

use std::collections::HashMap;

use spurs::{cmd, Execute, SshShell};

use super::paths;

pub use super::{
    dump_sys_info, oomkiller_blacklist_by_name, set_kernel_printk_level, turn_off_watchdogs, Login,
    ServiceAction,
};

/// The port that vagrant VMs forward from.
pub const VAGRANT_PORT: u16 = 5555;

/// The default amount of memory of the VM.
pub const VAGRANT_MEM: usize = 1024;

/// The default number of cores of the VM.
pub const VAGRANT_CORES: usize = 1;

/// The default value for /proc/zerosim_skip_halt.
///
/// Turning this on breaks the x86 ISA contract. Don't do that unless you know what you're about.
pub const ZEROSIM_SKIP_HALT: bool = false;

/// The default value for /proc/zerosim_lapic_adjust.
pub const ZEROSIM_LAPIC_ADJUST: bool = true;

/// Shut off any virtual machine and reboot the machine and do nothing else. Useful for getting the
/// machine into a clean state.
pub fn initial_reboot<A>(login: &Login<A>) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Connect to the remote
    let mut ushell = SshShell::with_default_key(login.username, &login.host)?;

    // Reboot the remote to make sure we have a clean slate
    spurs_util::reboot(&mut ushell, /* dry_run */ false)?;

    Ok(())
}

/// Turn off all previous swap spaces, and turn on the configured ones (e.g. via
/// research-settings.json).
pub fn setup_swapping(shell: &SshShell) -> Result<(), failure::Error> {
    turn_off_swapdevs(shell)?;
    turn_on_swapdevs(shell)?;
    Ok(())
}

/// Set the scaling governor to "performance".
pub fn set_perf_scaling_gov(shell: &SshShell) -> Result<(), failure::Error> {
    shell.run(cmd!("sudo cpupower frequency-set -g performance",))?;
    Ok(())
}

/// Connects to the host, waiting for it to come up if necessary. Turn on only the swap devices we
/// want. Set the scaling governor. Returns the shell to the host.
pub fn connect_and_setup_host_only<A>(login: &Login<A>) -> Result<SshShell, failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Debug + std::fmt::Display + Clone,
{
    // Keep trying to connect until we succeed
    let ushell = {
        let mut shell;
        loop {
            shell = match SshShell::with_default_key(login.username, &login.host) {
                Ok(shell) => shell,
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_secs(10));
                    continue;
                }
            };
            match shell.run(cmd!("whoami")) {
                Ok(_) => break,
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_secs(10));
                    continue;
                }
            }
        }

        shell
    };

    dump_sys_info(&ushell)?;

    // Set up swapping
    setup_swapping(&ushell)?;

    set_perf_scaling_gov(&ushell)?;

    set_kernel_printk_level(&ushell, 5)?;

    Ok(ushell)
}

pub fn turn_off_swapdevs(shell: &SshShell) -> Result<(), failure::Error> {
    let devs = spurs_util::get_mounted_devs(shell, /* dry_run */ false)?;

    // Turn off all swap devs
    for (dev, mount) in devs {
        if mount == "[SWAP]" {
            shell.run(cmd!("sudo swapoff /dev/{}", dev))?;
        }
    }

    Ok(())
}

/// Returns a list of swap devices, with SSDs listed first.
pub fn list_swapdevs(shell: &SshShell) -> Result<Vec<String>, failure::Error> {
    let mut swapdevs = vec![];

    // Find out what swap devs are there
    let devs = spurs_util::get_unpartitioned_devs(shell, /* dry_run */ false)?;

    // Get the size of each one
    let sizes = spurs_util::get_dev_sizes(
        shell,
        devs.iter().map(String::as_str).collect(),
        /* dry_run */ false,
    )?;

    // Turn on the SSDs as swap devs
    for (dev, size) in devs.iter().zip(sizes.iter()) {
        if size == "447.1G" {
            swapdevs.push(dev.clone());
        }
    }

    // Turn on the HDDs as swap devs
    for (dev, size) in devs.iter().zip(sizes.iter()) {
        if ["1.1T", "1.8T", "2.7T", "3.7T", "931.5G"]
            .iter()
            .any(|s| s == size)
        {
            swapdevs.push(dev.clone());
        }
    }

    Ok(swapdevs)
}

/// Create and mount a thinly-partitioned swap device using device mapper. Device mapper
/// requires two devices: a metadata volume and a data volume. We use a file mounted as a
/// loopback device for the metadata volume and another arbitrary device as the data volume.
///
/// The metadata volume only needs to be a few megabytes large (e.g. 1GB would be overkill).
/// The data volume should be as large and fast as needed.
///
/// This is idempotent.
fn create_and_turn_on_thin_swap_inner(
    shell: &SshShell,
    meta_file: &str,
    data_dev: &str,
    new: bool,
) -> Result<(), failure::Error> {
    // Check if thin device is already created.
    let already = shell
        .run(cmd!("sudo dmsetup ls"))?
        .stdout
        .contains("mythin");

    if !already {
        // create loopback
        shell.run(cmd!("sudo losetup -f {}", meta_file))?;

        // find out which loopback device was created
        let out = shell.run(cmd!("sudo losetup -j {}", meta_file))?.stdout;
        let loopback = out.trim().split(':').next().expect("expected device name");

        // find out the size of the mapper_device
        let out = shell
            .run(cmd!("lsblk -o SIZE -b {} | sed '2q;d'", data_dev).use_bash())?
            .stdout;
        let mapper_device_size = out.trim().parse::<u64>().unwrap() >> 9; // 512B sectors

        // create a thin pool
        // - 0 is the start sector
        // - `mapper_device_size` is the end sector of the pool. This should be the size of the data device.
        // - `loopback` is the metadata device
        // - `mapper_device` is the data device
        // - 256000 = 128MB is the block size
        // - 0 indicates no dm event on low-watermark
        shell.run(cmd!(
            "sudo dmsetup create mypool --table \
             '0 {} thin-pool {} {} 256000 0'",
            mapper_device_size,
            loopback,
            data_dev,
        ))?;

        if new {
            // create a thin volume
            // - /dev/mapper/mypool is the name of the pool device above
            // - 0 is the sector number on the pool
            // - create_thin indicates the pool should create a new thin volume
            // - 0 is a unique 24-bit volume id
            shell.run(cmd!(
                "sudo dmsetup message /dev/mapper/mypool 0 'create_thin 0'"
            ))?;
        }

        // init the volume
        // - 0 is the start sector
        // - 21474836480 = 10TB is the end sector
        // - thin is the device type
        // - /dev/mapper/mypool is the pool to use
        // - 0 is the volume id from above
        shell.run(cmd!(
            "sudo dmsetup create mythin --table '0 21474836480 thin /dev/mapper/mypool 0'"
        ))?;

        shell.run(cmd!("sudo mkswap /dev/mapper/mythin"))?;
    }

    shell.run(cmd!("sudo swapon -d /dev/mapper/mythin"))?;

    Ok(())
}

/// Create and mount a thinly-partitioned swap device using device mapper. Device mapper
/// requires two devices: a metadata volume and a data volume. We use a file mounted as a
/// loopback device for the metadata volume and another arbitrary device as the data volume.
///
/// The metadata volume only needs to be a few megabytes large (e.g. 1GB would be overkill).
/// The data volume should be as large and fast as needed.
pub fn turn_on_thin_swap(
    shell: &SshShell,
    meta_file: &str,
    data_dev: &str,
) -> Result<(), failure::Error> {
    create_and_turn_on_thin_swap_inner(shell, meta_file, data_dev, false)
}

/// Create a new thinly-partitioned swap device using device mapper. Device mapper
/// requires two devices: a metadata volume and a data volume. We use a file mounted as a
/// loopback device for the metadata volume and another arbitrary device as the data volume.
///
/// The metadata volume only needs to be a few megabytes large (e.g. 1GB would be overkill).
/// The data volume should be as large and fast as needed.
pub fn create_thin_swap(
    shell: &SshShell,
    meta_file: &str,
    data_dev: &str,
) -> Result<(), failure::Error> {
    create_and_turn_on_thin_swap_inner(shell, meta_file, data_dev, true)
}

/// Turn on swap devices. This function will respect any `swap-devices` setting in
/// `research-settings.json`. If there are no such settings, then all unpartitioned, unmounted
/// swap devices of the right size are used (according to `list_swapdevs`).
pub fn turn_on_swapdevs(shell: &SshShell) -> Result<(), failure::Error> {
    // Find out what swap devs are there
    let settings = crate::get_remote_research_settings(shell)?;

    if let (Some(dm_meta), Some(dm_data)) = (
        crate::get_remote_research_setting(&settings, "dm-meta")?,
        crate::get_remote_research_setting(&settings, "dm-data")?,
    ) {
        // If a thinly-provisioned swap space is setup, load and mount it.
        return turn_on_thin_swap(shell, dm_meta, dm_data);
    }

    let devs = if let Some(devs) = crate::get_remote_research_setting(&settings, "swap-devices")? {
        devs
    } else {
        list_swapdevs(shell)?
    };

    // Turn on swap devs
    for dev in &devs {
        shell.run(cmd!("sudo swapon -d /dev/{}", dev))?;
    }

    shell.run(cmd!("lsblk"))?;

    Ok(())
}

/// Turn on swap devices and SSDSWAP. This function will respect any `swap-devices` setting in
/// `research-settings.json`. If there are no such settings, then all unpartitioned, unmounted
/// swap devices of the right size are used (according to `list_swapdevs`).
pub fn turn_on_ssdswap(shell: &SshShell) -> Result<(), failure::Error> {
    // Find out what swap devs are there
    let settings = crate::get_remote_research_settings(shell)?;
    let devs = if let Some(dm_data) =
        crate::get_remote_research_setting::<String>(&settings, "dm-data")?
    {
        // If the swap device in use is a thin swap
        vec![
            dm_data.replace("/dev/", ""),
            "mapper/mythin".into(),
            "mapper/mypool".into(),
        ]
    } else if let Some(devs) = crate::get_remote_research_setting(&settings, "swap-devices")? {
        devs
    } else {
        list_swapdevs(shell)?
    };

    // Use SSDSWAP
    for dev in &devs {
        shell.run(
            cmd!(
                "echo /dev/{} | sudo tee /sys/module/ssdswap/parameters/device",
                dev
            )
            .use_bash(),
        )?;
    }

    // Remount all swap devs
    turn_off_swapdevs(shell)?;
    turn_on_swapdevs(shell)?;

    shell.run(cmd!("lsblk -o NAME,ROTA"))?;

    Ok(())
}

/// Get the VM domain name from `virsh` for the first running VM if there is a VM running or
/// the first stopped VM if no VM is running. The `bool` returned indicates whether the VM is
/// running or not (`true` is running).
pub fn virsh_domain_name(shell: &SshShell) -> Result<(String, bool), failure::Error> {
    let running: String = shell
        .run(cmd!(
            "sudo virsh list | tail -n 2 | head -n1 | awk '{{print $2}}'"
        ))?
        .stdout
        .trim()
        .into();

    if running.is_empty() {
        Ok((
            shell
                .run(cmd!(
                    "sudo virsh list --all | tail -n 2 | head -n1 | awk '{{print $2}}'"
                ))?
                .stdout
                .trim()
                .into(),
            false,
        ))
    } else {
        Ok((running, true))
    }
}

/// For `(v, p)` in `mapping`, pin vcpu `v` to host cpu `p`. `running` indicates whether the VM
/// is running or not.
pub fn virsh_vcpupin(
    shell: &SshShell,
    mapping: &HashMap<usize, usize>,
) -> Result<(), failure::Error> {
    let (domain, running) = virsh_domain_name(shell)?;

    // We may have just changed the number of vcpus in the vagrant config, so we need to make
    // sure that libvirt is up to date.
    with_shell! { shell =>
        cmd!(
            "sudo virsh setvcpus {} {} --maximum --config",
            domain,
            mapping.len(),
        ),
        cmd!(
            "sudo virsh setvcpus {} {} --config",
            domain,
            mapping.len(),
        ),
    }

    shell.run(cmd!("sudo virsh vcpuinfo {}", domain))?;

    for (v, p) in mapping {
        shell.run(cmd!(
            "sudo virsh vcpupin {} {} {} {}",
            domain,
            if running { "" } else { "--config" },
            v,
            p
        ))?;
    }

    shell.run(cmd!("sudo virsh vcpupin {}", domain))?;

    Ok(())
}

/// Generate a Vagrantfile for a VM with the given amount of memory and number of cores. A
/// Vagrantfile should already exist containing the correct domain name.
pub fn gen_vagrantfile(shell: &SshShell, memgb: usize, cores: usize) -> Result<(), failure::Error> {
    let vagrant_path = &format!(
        "{}/{}",
        paths::RESEARCH_WORKSPACE_PATH,
        paths::VAGRANT_SUBDIRECTORY
    );

    // Keep the same VM domain name and box type though...
    let current_name =
        shell.run(cmd!("grep -oE ':test_vm[0-9a-zA-Z_]+' Vagrantfile").cwd(vagrant_path))?;
    let current_name = current_name.stdout.trim();

    let current_box = shell.run(
        cmd!(r#"grep -oE 'vagrant_box = ".*"' Vagrantfile | awk '{{print $3}}'"#).cwd(vagrant_path),
    )?;
    let current_box = current_box.stdout.trim();

    with_shell! { shell in vagrant_path =>
        cmd!("cp Vagrantfile.bk Vagrantfile"),
        cmd!(r#"sed -i 's/^vagrant_vm_name = :test_vm$/vagrant_vm_name = {}/' Vagrantfile"#, current_name),
        // NOTE: the box name already contains "quotes"
        cmd!(r#"sed -i 's|^vagrant_box = .*$|vagrant_box = {}|' Vagrantfile"#, current_box),
        cmd!(r#"sed -i 's/^vagrant_vmem_gb = 20$/vagrant_vmem_gb = {}/' Vagrantfile"#, memgb),
        cmd!(r#"sed -i 's/^vagrant_vcpus = 1$/vagrant_vcpus = {}/' Vagrantfile"#, cores),
    }

    let user_home = crate::get_user_home_dir(shell)?;
    let vagrant_full_path = &format!("{}/{}", user_home, vagrant_path).replace("/", r#"\/"#);
    let vm_shared_full_path =
        &format!("{}/{}", user_home, paths::setup00000::HOSTNAME_SHARED_DIR).replace("/", r#"\/"#);
    let research_workspace_full_path =
        &format!("{}/{}", user_home, paths::RESEARCH_WORKSPACE_PATH).replace("/", r#"\/"#);

    with_shell! { shell in vagrant_path =>
        cmd!(
            r#"sed -i 's/^vagrant_dir = .*$/vagrant_dir = "{}"/' Vagrantfile"#,
            vagrant_full_path
        ),
        cmd!(
            r#"sed -i 's/^vm_shared_dir = .*$/vm_shared_dir = "{}"/' Vagrantfile"#,
            vm_shared_full_path
        ),
        cmd!(
            r#"sed -i 's/^zerosim_workspace_dir = .*$/zerosim_workspace_dir = "{}"/' Vagrantfile"#,
            research_workspace_full_path
        ),
    }

    // Choose the interface that actually gives network access. We do this by looking for the
    // interface that gives a route 1.1.1.1 (Cloudflare DNS).
    let iface = shell.run(
        cmd!(
            r#"/usr/sbin/ip route get 1.1.1.1 |\
                         grep -oE 'dev [a-z0-9]+ ' |\
                         awk '{{print $2}}'"#
        )
        .use_bash(),
    )?;
    let iface = iface.stdout.trim();

    shell.run(
        cmd!(
            r#"sed -i 's/^iface = .*$/iface = "{}"/' Vagrantfile"#,
            iface
        )
        .cwd(vagrant_path),
    )?;
    Ok(())
}

/// Set a command line argument for the kernel. If the argument is already their, it will be
/// replaced with the new value. Otherwise, it will be appended to the list of arguments.
///
/// Requires `sudo` (obviously).
///
/// It is advised that the caller manually shutdown the guest via `sudo poweorff` to avoid
/// corruption of the guest image.
pub fn set_kernel_boot_param(
    shell: &SshShell,
    param: &str,
    value: Option<&str>,
) -> Result<(), failure::Error> {
    let current_cmd_line = shell
        .run(
            cmd!(r#"cat /etc/default/grub | grep -oP 'GRUB_CMDLINE_LINUX="\K.+(?=")'"#).use_bash(),
        )?
        .stdout;
    let current_cmd_line = current_cmd_line
        .trim()
        .replace("/", r"\/")
        .replace(r"\", r"\\");

    // Remove parameters from existing command line
    let stripped_cmd_line = current_cmd_line
        .split_whitespace()
        .filter(|p| !p.starts_with(param))
        .collect::<Vec<_>>()
        .join(" ");

    // Add the new params.
    shell.run(cmd!(
        "sudo sed -i 's/{}/{} {}/' /etc/default/grub",
        current_cmd_line,
        stripped_cmd_line,
        if let Some(value) = value {
            format!("{}={}", param, value)
        } else {
            param.into()
        }
    ))?;

    // Rebuild grub conf
    shell.run(cmd!("sudo grub2-mkconfig -o /boot/grub2/grub.cfg"))?;

    // Sync to help avoid corruption
    shell.run(cmd!("sync"))?;

    Ok(())
}

/// Gathers some common stats for any 0sim simulation. This is intended to be called after the
/// simulation.
///
/// `sim_file` should be just the file name, not the directory path. This function will cause the
/// output to be in the standard locations.
///
/// Requires `sudo`.
pub fn gen_standard_sim_output(
    sim_file: &str,
    ushell: &SshShell,
    vshell: &SshShell,
) -> Result<(), failure::Error> {
    let guest_sim_file = dir!(paths::setup00000::VAGRANT_RESULTS_DIR, sim_file);

    crate::gen_standard_host_output(sim_file, ushell)?;

    vshell.run(cmd!(
        "echo -e '\nSimulation Stats (Guest)\n=====' >> {}",
        guest_sim_file
    ))?;
    vshell.run(cmd!("cat /proc/meminfo >> {}", guest_sim_file))?;

    vshell.run(cmd!(
        "echo -e '\ndmesg (Guest)\n=====' >> {}",
        guest_sim_file
    ))?;
    vshell.run(cmd!("dmesg >> {}", guest_sim_file))?;

    vshell.run(cmd!("sync"))?;

    Ok(())
}
