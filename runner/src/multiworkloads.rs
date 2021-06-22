//! Common workloads with multiple processes.

use std::{collections::HashMap, time::Instant};

use spurs::{cmd, Execute, SshShell, SshSpawnHandle};

use crate::workloads::{
    gen_cb_wrapper_command_prefix, run_memhog, run_metis_matrix_mult, run_redis_gen_data,
    start_redis, MemhogOptions, RedisWorkloadConfig, TasksetCtx,
};

/// Implemented common abilities for multi-process workloads.
pub trait MultiProcessWorkload {
    /// A bunch of the methods of this trait take a `key` that identifies which process in the
    /// workload to apply the method to. This allows, e.g., adding a prefix only to one command.
    ///
    /// If no key is needed, one can just use `()`.
    type Key: WorkloadKey;

    /// Return a list of process names in the workload.
    fn process_names() -> Vec<String>;

    /// Add a prefix to the command specified by the key.
    fn add_command_prefix(&mut self, key: Self::Key, prefix: &str);

    /// Start any background processes needed by this workload.
    fn start_background_processes(
        &mut self,
        shell: &SshShell,
    ) -> Result<Vec<SshSpawnHandle>, failure::Error>;

    /// Run the workload, blocking until it is complete.
    fn run_sync(&mut self, shell: &SshShell) -> Result<(), failure::Error>;
}

/// Any type that can act as a workload key for specifying which process in a workload to apply an
/// operation to.
pub trait WorkloadKey: Copy {
    fn from_name<S: AsRef<str>>(name: S) -> Self;
}

impl WorkloadKey for () {
    fn from_name<S: AsRef<str>>(_: S) -> Self {
        ()
    }
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
    /// The _host_ CPU frequency in MHz.
    freq: usize,
    /// The total amount of memory of the mix workload in GB.
    size_gb: usize,
    tctx: &'s mut TasksetCtx,
    runtime_file: &'s str,

    prefixes: HashMap<MixWorkloadKey, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MixWorkloadKey {
    Redis,
    Metis,
    Memhog,
}

impl WorkloadKey for MixWorkloadKey {
    fn from_name<S: AsRef<str>>(name: S) -> Self {
        match name.as_ref() {
            "redis-server" => Self::Redis,
            "matrix_mult2" => Self::Metis,
            "memhog" => Self::Memhog,
            k => panic!("Unknown key: {}", k),
        }
    }
}

impl MixWorkload<'_> {
    pub fn new<'s>(
        exp_dir: &'s str,
        metis_dir: &'s str,
        numactl_dir: &'s str,
        nullfs_dir: &'s str,
        redis_conf: &'s str,
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
            freq,
            size_gb,
            tctx,
            runtime_file,

            prefixes: HashMap::new(),
        }
    }

    pub fn set_mmap_filters(
        &mut self,
        cb_wrapper_path: &str,
        filters: HashMap<MixWorkloadKey, String>,
    ) {
        for (key, file) in filters.into_iter() {
            self.add_command_prefix(key, &gen_cb_wrapper_command_prefix(cb_wrapper_path, file));
        }
    }
}

impl MultiProcessWorkload for MixWorkload<'_> {
    type Key = MixWorkloadKey;

    fn process_names() -> Vec<String> {
        vec![
            "redis-server".into(),
            "matrix_mult2".into(),
            "memhog".into(),
        ]
    }

    fn add_command_prefix(&mut self, key: Self::Key, prefix: &str) {
        self.prefixes
            .entry(key)
            .or_insert_with(Vec::new)
            .push(prefix.into());
    }

    fn start_background_processes(
        &mut self,
        shell: &SshShell,
    ) -> Result<Vec<SshSpawnHandle>, failure::Error> {
        let prefixes = self
            .prefixes
            .get(&MixWorkloadKey::Redis)
            .map(|prefixes| prefixes.join(" "));

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
                // HACK: We reuse the cb_wrapper_cmd parameter to pass arbitrary prefixes here...
                cb_wrapper_cmd: prefixes.as_ref().map(String::as_str),
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
                cb_wrapper_cmd: None, // Ignored
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
            // HACK: We reuse the cb_wrapper_cmd parameter to pass arbitrary prefixes here...
            self.prefixes
                .get(&MixWorkloadKey::Metis)
                .map(|prefixes| prefixes.join(" "))
                .as_ref()
                .map(String::as_str),
            self.tctx,
        )?;

        let _memhog_handles = run_memhog(
            shell,
            self.numactl_dir,
            None, // repeat indefinitely
            (self.size_gb << 20) / 3,
            MemhogOptions::PIN | MemhogOptions::DATA_OBLIV,
            // HACK: We reuse the cb_wrapper_cmd parameter to pass arbitrary prefixes here...
            self.prefixes
                .get(&MixWorkloadKey::Memhog)
                .map(|prefixes| prefixes.join(" "))
                .as_ref()
                .map(String::as_str),
            self.tctx,
        )?;

        // Wait for redis client to finish
        redis_client_handle.join().1?;

        // Make sure processes die so that perf terminates.
        shell.run(cmd!("pkill -9 redis-server"))?;
        shell.run(cmd!("pkill -9 memhog"))?;
        shell.run(cmd!("pkill -9 matrix_mult2"))?;

        // Make sure perf is done.
        shell.run(cmd!(
            "while [[ $(pgrep -f '^perf stat') ]] ; do sleep 1 ; done ; echo done"
        ))?;

        let duration = Instant::now() - start;
        shell.run(cmd!(
            "echo '{}' > {}",
            duration.as_millis(),
            self.runtime_file
        ))?;

        Ok(())
    }
}

pub struct CloudsuiteWebServingWorkload<'s> {
    load_scale: usize,
    output_file: &'s str,

    prefixes: HashMap<CloudsuiteWebServingWorkloadKey, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CloudsuiteWebServingWorkloadKey {
    Mysql,
    Memcached,
    Nginx, // Nginx -- has multiple processes
           //Hhvm,
           //HHSingleCompile
}

impl WorkloadKey for CloudsuiteWebServingWorkloadKey {
    fn from_name<S: AsRef<str>>(name: S) -> Self {
        match name.as_ref() {
            "mysqld" => Self::Mysql,
            "memcached" => Self::Memcached,
            "nginx" => Self::Nginx,

            k => panic!("Unknown key: {}", k),
        }
    }
}

impl CloudsuiteWebServingWorkload<'_> {
    pub fn new<'s>(load_scale: usize, output_file: &'s str) -> CloudsuiteWebServingWorkload<'s> {
        CloudsuiteWebServingWorkload {
            load_scale,
            output_file,

            prefixes: HashMap::new(),
        }
    }
}

impl MultiProcessWorkload for CloudsuiteWebServingWorkload<'_> {
    type Key = CloudsuiteWebServingWorkloadKey;

    fn process_names() -> Vec<String> {
        vec!["mysqld".into(), "memcached".into(), "nginx".into(), todo!()]
    }

    fn add_command_prefix(&mut self, _key: Self::Key, _prefix: &str) {
        unimplemented!()
    }

    fn start_background_processes(
        &mut self,
        shell: &SshShell,
    ) -> Result<Vec<SshSpawnHandle>, failure::Error> {
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

            // Run the client to ensure that the servers have started.
            cmd!("docker run --pid=\"host\" --rm --net=host --name=faban_client \
                  cloudsuite/web-serving:faban_client \
                  $(hostname -I | awk '{{print $1}}') 1"),
        }

        Ok(vec![])
    }

    fn run_sync(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
        /* TODO
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
        */

        // Run workload
        shell.run(cmd!(
            "docker run --pid=\"host\" --rm --net=host --name=faban_client \
             cloudsuite/web-serving:faban_client \
             $(hostname -I | awk '{{print $1}}') {} \
             | tee {}",
            self.load_scale,
            self.output_file
        ))?;

        Ok(())
    }
}
