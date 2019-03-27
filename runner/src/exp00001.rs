//! Run the time_mmap_touch workload on the remote desktop machine.
//!
//! Requires the desktop machine to already be set up, similarly to `setup00000`, with a minor
//! exception: we run everything as root.

use spurs::{cmd, ssh::Execute};

use crate::common::exp00001::*;

pub fn run<A>(
    dry_run: bool,
    login: &Login<A>,
    size: usize,
    pattern: &str,
) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug,
{
    // Reboot
    initial_reboot(dry_run, &login.host)?;

    // Connect
    let (_ushell, mut rshell, vshell) = connect_and_setup_host_and_vagrant(dry_run, &login)?;

    // Environment
    turn_on_zswap(&mut rshell, dry_run)?;

    rshell.run(cmd!("echo 50 > /sys/module/zswap/parameters/max_pool_percent").use_bash())?;

    // Warm up
    //const WARM_UP_SIZE: usize = 50; // GB
    const WARM_UP_PATTERN: &str = "-z";
    vshell.run(
        cmd!(
            "./target/release/time_mmap_touch {} {} > /dev/null",
            //(WARM_UP_SIZE << 30) >> 12,
            //WARM_UP_PATTERN,
            (size << 30) >> 12,
            WARM_UP_PATTERN,
        )
        .cwd("/home/vagrant/0sim-experiments")
        .use_bash(),
    )?;

    // Then, run the actual experiment
    vshell.run(
        cmd!("./target/release/time_mmap_touch {} {} > /vagrant/vm_shared/results/time_mmap_touch_{}gb_zero_zswap_ssdswap_{}.out",
             (size << 30) >> 12,
             pattern,
             size,
             chrono::offset::Local::now().format("%Y-%m-%d-%H-%M-%S").to_string()
        )
        .cwd("/home/vagrant/0sim-experiments")
        .use_bash()
    )?;

    reboot(&mut rshell, dry_run)?;

    Ok(())
}