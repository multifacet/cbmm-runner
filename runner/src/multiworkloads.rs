//! Common workloads with multiple processes.

use std::time::Instant;

use spurs::{cmd, Execute, SshShell, SshSpawnHandle};

use crate::workloads::{
    run_memhog, run_metis_matrix_mult, run_redis_gen_data, start_redis, MemhogOptions,
    RedisWorkloadConfig, TasksetCtx,
};

/// Implemented common abilities for multi-process workloads. Not all of these operations need to
/// be implemented; the default implementation for unsupported operations just panics.
pub trait MultiProcessWorkload {
    /// A bunch of the methods of this trait take a `key` that identifies which process in the
    /// workload to apply the method to. This allows, e.g., adding a prefix only to one command.
    ///
    /// If no key is needed, one can just use `()`.
    type Key: Copy;

    /// Return a list of process names in the workload.
    fn process_names() -> Vec<String>;

    /// Add a prefix to the command specified by the key.
    fn add_command_prefix(&mut self, _key: Self::Key, _prefix: &str) {
        unimplemented!();
    }

    /// Start any background processes needed by this workload.
    fn start_background_processes(
        &mut self,
        shell: &SshShell,
    ) -> Result<Vec<SshSpawnHandle>, failure::Error>;

    /// Run the workload, blocking until it is complete.
    fn run_sync(&mut self, shell: &SshShell) -> Result<(), failure::Error>;
}

/// Run the mix workload which consists of splitting memory between
///
/// - 1 data-obliv memhog process with memory pinning (running indefinitely)
/// - 1 redis server and client pair. The redis server does snapshots every minute.
/// - 1 metis instance doing matrix multiplication
///
/// This workload runs until the redis subworkload completes.
///
/// Given a requested workload size of `size_gb` GB, each sub-workload gets 1/3 of the space.
#[derive(Debug)]
pub struct MixWorkload<'s> {
    /// The path of the `0sim-experiments` submodule on the remote.
    exp_dir: &'s str,
    /// The path to the `Metis` directory in the workspace on the remote.
    metis_dir: &'s str,
    /// The path to the `numactl` directory in the workspace on the remote.
    numactl_dir: &'s str,
    nullfs_dir: &'s str,
    /// The path to the `redis.conf` file on the remote.
    redis_conf: &'s str,
    /// The cb_wrapper command prefix (it is reused for all commands).
    cb_wrapper_cmd: Option<&'s str>,
    /// The _host_ CPU frequency in MHz.
    freq: usize,
    /// The total amount of memory of the mix workload in GB.
    size_gb: usize,
    tctx: &'s mut TasksetCtx,
    runtime_file: &'s str,
}

impl MixWorkload<'_> {
    pub fn new<'s>(
        exp_dir: &'s str,
        metis_dir: &'s str,
        numactl_dir: &'s str,
        nullfs_dir: &'s str,
        redis_conf: &'s str,
        cb_wrapper_cmd: Option<&'s str>,
        freq: usize,
        size_gb: usize,
        tctx: &'s mut TasksetCtx,
        runtime_file: &'s str,
    ) -> MixWorkload<'s> {
        MixWorkload {
            exp_dir,
            metis_dir,
            numactl_dir,
            nullfs_dir,
            redis_conf,
            cb_wrapper_cmd,
            freq,
            size_gb,
            tctx,
            runtime_file,
        }
    }
}

impl MultiProcessWorkload for MixWorkload<'_> {
    type Key = ();

    fn process_names() -> Vec<String> {
        vec![
            "redis-server".into(),
            "matrix_mult2".into(),
            "memhog".into(),
        ]
    }

    fn start_background_processes(
        &mut self,
        shell: &SshShell,
    ) -> Result<Vec<SshSpawnHandle>, failure::Error> {
        // Start server
        let server_spawn_handle = start_redis(
            &shell,
            &RedisWorkloadConfig {
                exp_dir: self.exp_dir,
                nullfs: self.nullfs_dir,
                server_size_mb: (self.size_gb << 10) / 3,
                wk_size_gb: self.size_gb / 3,
                freq: Some(self.freq),
                pf_time: None,
                output_file: None,
                cb_wrapper_cmd: self.cb_wrapper_cmd.clone(),
                client_pin_core: self.tctx.next(),
                server_pin_core: None,
                redis_conf: self.redis_conf,
                pintool: None,
            },
        )?;

        Ok(vec![server_spawn_handle])
    }

    fn run_sync(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
        let start = Instant::now();

        let redis_client_handle = run_redis_gen_data(
            shell,
            &RedisWorkloadConfig {
                exp_dir: self.exp_dir,
                nullfs: self.nullfs_dir,
                server_size_mb: (self.size_gb << 10) / 3,
                wk_size_gb: self.size_gb / 3,
                freq: Some(self.freq),
                pf_time: None,
                output_file: None,
                cb_wrapper_cmd: self.cb_wrapper_cmd.clone(),
                client_pin_core: self.tctx.next(),
                server_pin_core: None,
                redis_conf: self.redis_conf,
                pintool: None,
            },
        )?;

        let matrix_dim = (((self.size_gb / 3) << 27) as f64).sqrt() as usize;
        let _metis_handle = run_metis_matrix_mult(
            shell,
            self.metis_dir,
            matrix_dim,
            self.cb_wrapper_cmd.clone(),
            self.tctx,
        )?;

        let _memhog_handles = run_memhog(
            shell,
            self.numactl_dir,
            None,
            (self.size_gb << 20) / 3,
            MemhogOptions::PIN | MemhogOptions::DATA_OBLIV,
            self.cb_wrapper_cmd,
            self.tctx,
        )?;

        // Wait for redis client to finish
        redis_client_handle.join().1?;

        let duration = Instant::now() - start;
        shell.run(cmd!(
            "echo '{}' > {}",
            duration.as_millis(),
            self.runtime_file
        ))?;

        Ok(())
    }
}

pub fn run_cloudsuite_web_serving(
    shell: &SshShell,
    load_scale: usize,
    benefit_file: Option<&str>,
    output_file: &str,
) -> Result<(), failure::Error> {
    // Start db, cache, webserver.
    with_shell! { shell =>
        cmd!("docker run -dt --pid=\"host\" --rm --net=host --name=mysql_server \
              cloudsuite/web-serving:db_server \
              $(hostname -I | awk '{{print $1}}')"),
        cmd!("docker run -dt --pid=\"host\" --rm --net=host --name=memcache_server \
              cloudsuite/web-serving:memcached_server"),
        cmd!("WSIP=$(hostname -I | awk '{{print $1}}')
              docker run -e \"HHVM=true\" -dt --pid=\"host\" --rm --net=host \
              --name=web_server_local cloudsuite/web-serving:web_server \
              /etc/bootstrap.sh $WSIP $WSIP"),
    }

    // Run the client to ensure that the servers have started.
    shell.run(cmd!(
        "docker run --pid=\"host\" --rm --net=host --name=faban_client \
         cloudsuite/web-serving:faban_client \
         $(hostname -I | awk '{{print $1}}') 1",
    ))?;

    // TODO: would make sense to have different benefits file for different processes :/
    // Set CBMM benefits.
    if let Some(benefits_file) = benefit_file {
        shell.run(cmd!(
            "cat {} | sudo tee /proc/`pgrep mysqld`/mmap_filters",
            benefits_file
        ))?;
        shell.run(cmd!(
            "cat {} | sudo tee /proc/`pgrep memcached`/mmap_filters",
            benefits_file
        ))?;
        shell.run(cmd!(
            "for p in $(pgrep hhvm) ; do cat {} | sudo tee /proc/$p/mmap_filters ; done",
            benefits_file
        ))?;
        shell.run(cmd!(
            "for p in $(pgrep hh_single_compile) ; do cat {} | sudo tee /proc/$p/mmap_filters ; done",
            benefits_file
        ))?;
        shell.run(cmd!(
            "for p in $(pgrep nginx) ; do cat {} | sudo tee /proc/$p/mmap_filters ; done",
            benefits_file
        ))?;
    }

    // Run workload
    shell.run(cmd!(
        "docker run --pid=\"host\" --rm --net=host --name=faban_client \
         cloudsuite/web-serving:faban_client \
         $(hostname -I | awk '{{print $1}}') {} \
         | tee {}",
        load_scale,
        output_file
    ))?;

    Ok(())
}
