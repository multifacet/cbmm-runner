//! Common workloads with multiple processes.

use std::{collections::HashMap, time::Instant};

use rand::{rngs::SmallRng, SeedableRng};

use spurs::{cmd, Execute, SshShell, SshSpawnHandle};

use crate::workloads::{
    gen_cb_wrapper_command_prefix, gen_perf_command_prefix, run_memhog, run_metis_matrix_mult,
    run_redis_gen_data, start_redis, MemhogOptions, RedisWorkloadConfig, TasksetCtx, YcsbConfig,
    YcsbSession, YcsbSystem, YcsbWorkload,
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

    /// Forcibly kill any background processes started by this workload.
    fn kill_background_processes(&mut self, shell: &SshShell) -> Result<(), failure::Error>;
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
    nullfs_dir: Option<&'s str>,
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

/// Like `MixWorkload`, but redis is driven by YCSB.
pub struct MixYcsbWorkload<'s> {
    /// The path of the `0sim-experiments` submodule on the remote.
    exp_dir: &'s str,
    /// The path to the `Metis` directory in the workspace on the remote.
    metis_dir: &'s str,
    /// The path to the `numactl` directory in the workspace on the remote.
    numactl_dir: &'s str,
    nullfs_dir: Option<&'s str>,
    /// The path to the `redis.conf` file on the remote.
    redis_conf: &'s str,
    /// The path of the YCSB directory.
    ycsb_path: &'s str,
    /// Path for the results file of the YCSB output
    ycsb_result_file: Option<&'s str>,
    /// The YCSB workload to use.
    ycsb_workload: YcsbWorkload,
    /// The _host_ CPU frequency in MHz.
    freq: usize,
    /// The total amount of memory of the mix workload in GB.
    size_gb: usize,
    tctx: &'s mut TasksetCtx,
    runtime_file: &'s str,

    prefixes: HashMap<MixWorkloadKey, Vec<String>>,
    ycsb: Option<YcsbSession<'s, for<'a> fn(&'a SshShell) -> Result<(), failure::Error>>>,
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
        nullfs_dir: Option<&'s str>,
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
                cb_wrapper_cmd: prefixes,
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
        shell.run(cmd!("sudo pkill -9 redis-server"))?;
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

    fn kill_background_processes(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
        shell.run(cmd!("sudo pkill -9 redis-server"))?;
        Ok(())
    }
}

impl MixYcsbWorkload<'_> {
    pub fn new<'s>(
        exp_dir: &'s str,
        metis_dir: &'s str,
        numactl_dir: &'s str,
        nullfs_dir: Option<&'s str>,
        redis_conf: &'s str,
        ycsb_path: &'s str,
        ycsb_result_file: Option<&'s str>,
        ycsb_workload: YcsbWorkload,
        freq: usize,
        size_gb: usize,
        tctx: &'s mut TasksetCtx,
        runtime_file: &'s str,
    ) -> MixYcsbWorkload<'s> {
        MixYcsbWorkload {
            exp_dir,
            metis_dir,
            numactl_dir,
            nullfs_dir,
            redis_conf,
            ycsb_path,
            ycsb_result_file,
            ycsb_workload,
            freq,
            size_gb,
            tctx,
            runtime_file,

            ycsb: None,
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

impl MultiProcessWorkload for MixYcsbWorkload<'_> {
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

        let redis_cfg = RedisWorkloadConfig {
            exp_dir: self.exp_dir,
            nullfs: self.nullfs_dir,
            server_size_mb: (self.size_gb << 10) / 3,
            wk_size_gb: self.size_gb / 3,
            freq: Some(self.freq),
            pf_time: None,
            output_file: None,
            // HACK: We reuse the cb_wrapper_cmd parameter to pass arbitrary prefixes here...
            cb_wrapper_cmd: prefixes,
            client_pin_core: self.tctx.next(),
            server_pin_core: None,
            redis_conf: self.redis_conf,
            pintool: None,
        };

        let ycsb_cfg: YcsbConfig<for<'a> fn(&'a _) -> _> = YcsbConfig {
            workload: self.ycsb_workload,
            system: YcsbSystem::Redis(redis_cfg),
            ycsb_path: self.ycsb_path,
            ycsb_result_file: self.ycsb_result_file,
        };
        let mut ycsb = YcsbSession::new(ycsb_cfg);

        // Start servers and initial dataset...
        ycsb.start_and_load(shell)?;
        self.ycsb = Some(ycsb);

        Ok(vec![])
    }

    fn run_sync(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
        let start = Instant::now();

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

        // Blocks until completion...
        self.ycsb.as_mut().unwrap().run(shell)?;

        // Make sure processes die so that perf terminates.
        shell.run(cmd!("sudo pkill -9 redis-server"))?;
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

    fn kill_background_processes(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
        shell.run(cmd!("sudo pkill -9 redis-server"))?;
        Ok(())
    }
}

pub struct CloudsuiteWebServingWorkload<'s> {
    load_scale: usize,
    use_hhvm: bool,
    output_file: &'s str,

    /// Used to randomly select processes when needed.
    rng: SmallRng,
    /// Save the pids of the instrumented processes, since we might have chosen one of many
    /// processes at random.
    saved_pids: HashMap<CloudsuiteWebServingWorkloadKey, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcessSelector {
    Master,
    RandomWorker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CloudsuiteWebServingWorkloadKey {
    Mysql,
    Memcached,
    /// Nginx has a master and worker pool.
    Nginx(ProcessSelector),
    /// Selects one of the co-equal processes at random.
    Hhvm,
    HHSingleCompile,
    /// PhpFpm has a master and worker pool.
    PhpFpm(ProcessSelector),
}

impl WorkloadKey for CloudsuiteWebServingWorkloadKey {
    fn from_name<S: AsRef<str>>(name: S) -> Self {
        match name.as_ref() {
            "mysqld" => Self::Mysql,
            "memcached" => Self::Memcached,

            "nginx:master" => Self::Nginx(ProcessSelector::Master),
            "nginx:worker" => Self::Nginx(ProcessSelector::RandomWorker),

            "hhvm" => Self::Hhvm,
            "hh_single_compile" => Self::HHSingleCompile,

            "php-fpm:master" => Self::PhpFpm(ProcessSelector::Master),
            "php-fpm:pool" => Self::PhpFpm(ProcessSelector::RandomWorker),

            k => panic!("Unknown key: {}", k),
        }
    }
}

impl CloudsuiteWebServingWorkload<'_> {
    pub fn new<'s>(
        load_scale: usize,
        use_hhvm: bool,
        output_file: &'s str,
    ) -> CloudsuiteWebServingWorkload<'s> {
        CloudsuiteWebServingWorkload {
            load_scale,
            use_hhvm,
            output_file,

            rng: SmallRng::seed_from_u64(0),
            saved_pids: HashMap::new(),
        }
    }

    /// Get the PID for the/a process matching the key.
    fn key_to_pid(
        &mut self,
        shell: &SshShell,
        key: CloudsuiteWebServingWorkloadKey,
    ) -> Result<usize, failure::Error> {
        use rand::seq::SliceRandom;
        use CloudsuiteWebServingWorkloadKey::*;

        fn get_pids_by_name(
            shell: &SshShell,
            container: &str,
            name: &str,
            extra: &str,
        ) -> Result<Vec<usize>, failure::Error> {
            let pids = shell
                .run(cmd!(
                    "docker top {} -o pid -o command -A \
                     | grep -v 'sh -c ' | grep '{}' {} \
                     | awk '{{print $1}}'",
                    container,
                    name,
                    extra
                ))?
                .stdout
                .trim()
                .split_whitespace()
                .map(|pid_str| pid_str.trim().parse::<usize>().unwrap())
                .collect();

            Ok(pids)
        }

        if let Some(saved) = self.saved_pids.get(&key) {
            return Ok(*saved);
        }

        let pid = match key {
            // Unique processes
            Mysql => get_pids_by_name(shell, "mysql_server", "mysqld", "")?[0],
            Memcached => get_pids_by_name(shell, "memcache_server", "memcached", "")?[0],
            HHSingleCompile => {
                get_pids_by_name(shell, "web_server_local", "hh_single_compile", "")?[0]
            }
            Nginx(ProcessSelector::Master) => {
                get_pids_by_name(shell, "web_server_local", "nginx", "| grep master")?[0]
            }
            PhpFpm(ProcessSelector::Master) => {
                get_pids_by_name(shell, "web_server_local", "php-fpm", "| grep master")?[0]
            }

            // Random selection
            Hhvm => *get_pids_by_name(shell, "web_server_local", "hhvm", "")?
                .choose(&mut self.rng)
                .unwrap(),
            Nginx(ProcessSelector::RandomWorker) => {
                *get_pids_by_name(shell, "web_server_local", "nginx", "| grep worker")?
                    .choose(&mut self.rng)
                    .unwrap()
            }
            PhpFpm(ProcessSelector::RandomWorker) => {
                *get_pids_by_name(shell, "web_server_local", "php-fpm", "| grep pool")?
                    .choose(&mut self.rng)
                    .unwrap()
            }
        };

        self.saved_pids.insert(key, pid);

        Ok(pid)
    }

    /// Since the background processes run in docker containers, it's kind of a pain to run them
    /// with a prefix. Instead, we attach perf after starting them by specifying a PID to perf's
    /// `-p` argument.
    ///
    /// Obviously, this function should run after `start_background_processes` but not to long
    /// before running the workload. For the perf counters we have looked at so far, this makes the
    /// numbers look a bit higher, but the error is still orders of magnitude less than the numbers
    /// themselves, so it should be ok...
    pub fn attach_perf_stat(
        &mut self,
        shell: &SshShell,
        key: CloudsuiteWebServingWorkloadKey,
        mmu_overhead_file: &str,
        perf_counters: &[impl AsRef<str>],
    ) -> Result<SshSpawnHandle, failure::Error> {
        let pid = self.key_to_pid(shell, key)?;
        let handle = shell.spawn(cmd!(
            "sudo {}",
            gen_perf_command_prefix(mmu_overhead_file, perf_counters, format!("-p {}", pid))
        ))?;

        Ok(handle)
    }

    /// Similar to `attach_perf_stat`, but less time sensitive. Also, we set the benefits for all
    /// processes of a given type, rather than randomly selecting a worker.
    pub fn set_mmap_filters(
        &mut self,
        shell: &SshShell,
        filters: HashMap<CloudsuiteWebServingWorkloadKey, String>,
    ) -> Result<(), failure::Error> {
        for (key, benefits_file) in filters.iter() {
            match key {
                CloudsuiteWebServingWorkloadKey::Mysql => {
                    shell.run(cmd!(
                        "cat {} | sudo tee /proc/`pgrep mysqld`/mmap_filters",
                        benefits_file
                    ))?;
                }
                CloudsuiteWebServingWorkloadKey::Memcached => {
                    shell.run(cmd!(
                        "cat {} | sudo tee /proc/`pgrep memcached`/mmap_filters",
                        benefits_file
                    ))?;
                }
                CloudsuiteWebServingWorkloadKey::Hhvm => {
                    shell.run(cmd!(
                        "for p in $(pgrep hhvm) ; do \
                         cat {} | sudo tee /proc/$p/mmap_filters ; done",
                        benefits_file
                    ))?;
                }
                CloudsuiteWebServingWorkloadKey::HHSingleCompile => {
                    shell.run(cmd!(
                        "for p in $(pgrep hh_single_compile) ; do \
                         cat {} | sudo tee /proc/$p/mmap_filters ; done",
                        benefits_file
                    ))?;
                }
                CloudsuiteWebServingWorkloadKey::Nginx(ProcessSelector::Master) => {
                    shell.run(cmd!(
                        "for p in $(pgrep -f '^nginx: master') ; do \
                         cat {} | sudo tee /proc/$p/mmap_filters ; done",
                        benefits_file
                    ))?;
                }
                CloudsuiteWebServingWorkloadKey::Nginx(ProcessSelector::RandomWorker) => {
                    shell.run(cmd!(
                        "for p in $(pgrep -f '^nginx: worker') ; do \
                         cat {} | sudo tee /proc/$p/mmap_filters ; done",
                        benefits_file
                    ))?;
                }
                CloudsuiteWebServingWorkloadKey::PhpFpm(ProcessSelector::Master) => {
                    shell.run(cmd!(
                        "for p in $(pgrep -f '^php-fpm: master') ; do \
                         cat {} | sudo tee /proc/$p/mmap_filters ; done",
                        benefits_file
                    ))?;
                }
                CloudsuiteWebServingWorkloadKey::PhpFpm(ProcessSelector::RandomWorker) => {
                    shell.run(cmd!(
                        "for p in $(pgrep -f '^php-fpm: pool') ; do \
                         cat {} | sudo tee /proc/$p/mmap_filters ; done",
                        benefits_file
                    ))?;
                }
            }
        }

        Ok(())
    }
}

impl MultiProcessWorkload for CloudsuiteWebServingWorkload<'_> {
    type Key = CloudsuiteWebServingWorkloadKey;

    fn process_names() -> Vec<String> {
        vec![
            "mysqld".into(),
            "memcached".into(),
            "nginx".into(),
            "hhvm".into(),
            "hh_single_compile".into(),
            "php-fpm".into(),
        ]
    }

    fn add_command_prefix(&mut self, _key: Self::Key, _prefix: &str) {
        unimplemented!("see `attach_perf_stat()")
    }

    fn start_background_processes(
        &mut self,
        shell: &SshShell,
    ) -> Result<Vec<SshSpawnHandle>, failure::Error> {
        // Start db, cache, webserver.
        with_shell! { shell =>
            cmd!("docker run -dt --pid=host --rm --net=host --name=mysql_server \
                  cloudsuite/web-serving:db_server \
                  $(hostname -I | awk '{{print $1}}')"),
            cmd!("docker run -dt --pid=host --rm --net=host --name=memcache_server \
                  cloudsuite/web-serving:memcached_server"),
            cmd!("WSIP=$(hostname -I | awk '{{print $1}}')
                  docker run -e \"HHVM={}\" -dt --pid=host --rm --net=host \
                  --name=web_server_local cloudsuite/web-serving:web_server \
                  /etc/bootstrap.sh $WSIP $WSIP", self.use_hhvm),

            // Run the client to ensure that the servers have started.
            cmd!("docker run --pid=host --rm --net=host --name=faban_client \
                  cloudsuite/web-serving:faban_client \
                  $(hostname -I | awk '{{print $1}}') 1"),
        }

        Ok(vec![])
    }

    fn run_sync(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
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

    fn kill_background_processes(&mut self, shell: &SshShell) -> Result<(), failure::Error> {
        shell.run(cmd!("docker kill $(docker ps -q)"))?;
        Ok(())
    }
}
