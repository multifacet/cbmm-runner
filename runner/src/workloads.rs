//! Common workloads.

use bitflags::bitflags;

use super::get_user_home_dir;

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshError, SshShell, SshSpawnHandle};

use super::{oomkiller_blacklist_by_name, paths::EAGER_PAGING_SCRIPT};

pub const DEFAULT_DAMON_SAMPLE_INTERVAL: usize = 5 * 1000; // msecs
pub const DEFAULT_DAMON_AGGR_INTERVAL: usize = 100 * 1000; // msecs

/// Set the apriori paging process using Swapnil's program. Requires `sudo`.
///
/// For example, to cause `ls` to be eagerly paged:
///
/// ```rust,ignore
/// setup_apriori_paging_process(&shell, "ls")?;
/// ```
pub fn setup_apriori_paging_process(
    shell: &SshShell,
    swapnil_path: &str,
    prog: &str,
) -> Result<(), SshError> {
    shell.run(cmd!("{}/{} {}", swapnil_path, EAGER_PAGING_SCRIPT, prog))?;
    Ok(())
}

/// Keeps track of which guest vCPUs have been assigned.
#[derive(Debug)]
pub struct TasksetCtx {
    /// The total number of vCPUs.
    ncores: usize,

    /// The number of assignments so far.
    next: usize,
}

impl TasksetCtx {
    /// Create a new context with the given total number of cores.
    pub fn new(ncores: usize) -> Self {
        assert!(ncores > 0);
        TasksetCtx { ncores, next: 0 }
    }

    /// Skip one CPU. This is useful to avoid hyperthreading effects.
    pub fn skip(&mut self) {
        self.next += 1;
    }

    /// Get the next core (wrapping around to 0 if all cores have been assigned).
    pub fn next(&mut self) -> usize {
        let c = self.next % self.ncores;
        self.next += 1;
        c
    }
}

/// Indicates a Intel PIN pintool to run, along with the needed parameters.
#[derive(Debug)]
pub enum Pintool<'s> {
    /// Collect a memory trace.
    MemTrace {
        /// The path to the root of the `pin/` directory. This should be accessible in the VM.
        pin_path: &'s str,
        /// The file path and name to output the trace to.
        output_path: &'s str,
    },
}

/// Indicates the use of DAMON to trace page access rates.
#[derive(Debug)]
pub struct Damon<'s> {
    /// The path to the `damon/` directory. This should be accessible in the VM.
    pub damon_path: &'s str,
    /// The file path and name to output the trace to.
    pub output_path: &'s str,

    /// The interval (in ms) with which to sample the address space.
    pub sample_interval: usize,
    /// The interval (in ms) with which to aggregate samples.
    pub aggregate_interval: usize,
}

/// The different patterns supported by the `time_mmap_touch` workload.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum TimeMmapTouchPattern {
    Zeros,
    Counter,
}

/// Settings for a run of the `time_mmap_touch` workload.
#[derive(Debug)]
pub struct TimeMmapTouchConfig<'s> {
    /// The path of the `0sim-experiments` submodule on the remote.
    pub exp_dir: &'s str,

    /// The number of _pages_ to touch.
    pub pages: usize,
    /// Specifies the pattern to write to the pages.
    pub pattern: TimeMmapTouchPattern,

    /// The file to which the workload will write its output. If `None`, then `/dev/null` is used.
    pub output_file: Option<&'s str>,

    /// The core to pin the workload to in the guest.
    pub pin_core: usize,
    /// Specifies whether to prefault memory or not (true = yes).
    pub prefault: bool,
    /// Specifies the page fault time if TSC offsetting is to try to account for it.
    pub pf_time: Option<u64>,
    /// Indicates whether the workload should be run with eager paging (only in VM).
    pub eager: Option<&'s str>,
}

/// Run the `time_mmap_touch` workload on the remote `shell`. Requires `sudo`.
pub fn run_time_mmap_touch(
    shell: &SshShell,
    cfg: &TimeMmapTouchConfig<'_>,
) -> Result<(), failure::Error> {
    let pattern = match cfg.pattern {
        TimeMmapTouchPattern::Counter => "-c",
        TimeMmapTouchPattern::Zeros => "-z",
    };

    if let Some(swapnil_path) = cfg.eager {
        setup_apriori_paging_process(shell, swapnil_path, "time_mmap_touch")?;
    }

    shell.run(
        cmd!(
            "sudo taskset -c {} ./target/release/time_mmap_touch {} {} {} {} > {}",
            cfg.pin_core,
            cfg.pages,
            pattern,
            if cfg.prefault { "-p" } else { "" },
            if let Some(pf_time) = cfg.pf_time {
                format!("--pftime {}", pf_time)
            } else {
                "".into()
            },
            cfg.output_file.unwrap_or("/dev/null")
        )
        .cwd(cfg.exp_dir)
        .use_bash(),
    )?;

    Ok(())
}

/// The configuration of a memcached workload.
#[derive(Debug)]
pub struct MemcachedWorkloadConfig<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    /// The path of the `0sim-experiments` submodule on the remote.
    pub exp_dir: &'s str,
    /// The directory in which the memcached binary is contained.
    pub memcached: &'s str,

    /// The user to run the `memcached` server as.
    pub user: &'s str,
    /// The size of `memcached` server in MB.
    pub server_size_mb: usize,
    /// Specifies whether the memcached server is allowed to OOM.
    pub allow_oom: bool,

    /// The core number that the memcached server is pinned to, if any.
    pub server_pin_core: Option<usize>,
    /// The core number that the workload client is pinned to.
    pub client_pin_core: usize,

    /// The size of the workload in GB.
    pub wk_size_gb: usize,
    /// The file to which the workload will write its output. If `None`, then `/dev/null` is used.
    pub output_file: Option<&'s str>,

    /// The CPU frequency. If passed, the workload will use rdtsc for timing.
    pub freq: Option<usize>,
    /// Specifies the page fault time if TSC offsetting is to try to account for it.
    pub pf_time: Option<u64>,
    /// Indicates whether the workload should be run with eager paging.
    pub eager: Option<&'s str>,

    /// Indicates that we should run the given pintool on the workload.
    pub pintool: Option<Pintool<'s>>,

    /// Indicates that we should run the workload under DAMON.
    pub damon: Option<Damon<'s>>,

    /// Indicates that we should run the workload under `perf` to capture MMU overhead stats.
    /// The string is the path to the output.
    pub mmu_perf: Option<String>,

    /// A callback executed after the memcached server starts but before the workload starts.
    pub server_start_cb: F,
}

/// Start a `memcached` server in daemon mode as the given user with the given amount of memory.
/// Usually this is called indirectly through one of the other workload routines.
///
/// `allow_oom` specifies whether memcached is allowed to OOM. This gives much simpler performance
/// behaviors. memcached uses a large amount of the memory you give it for bookkeeping, rather
/// than user data, so OOM will almost certainly happen. memcached will also evict the LRU data in
/// this case.
///
/// `eager` indicates whether the workload should be run with eager paging (only in VM); if so, the
/// path to Swapnil's scripts must be passed.
pub fn start_memcached<F>(
    shell: &SshShell,
    cfg: &MemcachedWorkloadConfig<'_, F>,
) -> Result<Option<spurs::SshSpawnHandle>, failure::Error>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    if let Some(swapnil_path) = cfg.eager {
        setup_apriori_paging_process(shell, swapnil_path, "memcached")?;
    }

    // We need to update the system vma limit because malloc may cause it to be hit for
    // large-memory systems.
    shell.run(cmd!("sudo sysctl -w vm.max_map_count={}", 1_000_000_000))?;

    let taskset = if let Some(server_pin_core) = cfg.server_pin_core {
        format!("taskset -c {} ", server_pin_core)
    } else {
        "".into()
    };

    let pintool = match cfg.pintool {
        Some(Pintool::MemTrace {
            pin_path,
            output_path,
        }) => format!(
            "{}/pin -t {}/source/tools/MemTrace/obj-intel64/membuffer.so -o {} -emit -- ",
            pin_path, pin_path, output_path
        ),

        None => "".into(),
    };

    shell.run(cmd!(
        "{}{}{}/memcached {} -m {} -d -u {} -f 1.11 -v",
        pintool,
        taskset,
        cfg.memcached,
        if cfg.allow_oom { "-M" } else { "" },
        cfg.server_size_mb,
        cfg.user
    ))?;

    // Wait for memcached to start by using `memcached-tool` until we are able to connect.
    while let Err(..) = shell.run(cmd!("memcached-tool localhost:11211")) {}

    // Don't let memcached get OOM killed.
    oomkiller_blacklist_by_name(shell, "memcached")?;

    // Run the callback.
    (cfg.server_start_cb)(shell)?;

    // Start DAMON if needed.
    if let Some(damon) = &cfg.damon {
        shell.run(cmd!(
            "sudo {}/damo record -s {} -a {} -o {} `pidof memcached`",
            damon.damon_path,
            damon.sample_interval,
            damon.aggregate_interval,
            damon.output_path,
        ))?;
    }

    // Start `perf` if needed.
    Ok(if let Some(output_path) = &cfg.mmu_perf {
        let pagewalk_pc = super::page_walk_perf_counter_suffix(&shell)?;
        let handle = shell.spawn(cmd!(
            "perf stat \
            -e dtlb_load_misses.{} \
            -e dtlb_store_misses.{} \
            -e dtlb_load_misses.miss_causes_a_walk \
            -e dtlb_store_misses.miss_causes_a_walk \
            -e cpu_clk_unhalted.thread_any \
            -e inst_retired.any \
            -e faults \
            -e migrations \
            -e cs \
            -p `pgrep memcached` 2>&1 | \
            tee {}",
            pagewalk_pc,
            pagewalk_pc,
            output_path
        ))?;

        // Wait for perf to start collection.
        shell.run(cmd!("while [ ! -e {} ] ; do sleep 1 ; done", output_path).use_bash())?;

        Some(handle)
    } else {
        None
    })
}

/// Run the `memcached_gen_data` workload.
pub fn run_memcached_gen_data<F>(
    shell: &SshShell,
    cfg: &MemcachedWorkloadConfig<'_, F>,
) -> Result<(), failure::Error>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    // Start server
    let _handles = start_memcached(&shell, cfg)?;

    // Run workload
    let cmd = cmd!(
        "taskset -c {} ./target/release/memcached_gen_data localhost:11211 {} {} {} | tee {}",
        cfg.client_pin_core,
        cfg.wk_size_gb - 1, // Avoid a OOM
        if let Some(freq) = cfg.freq {
            format!("--freq {}", freq)
        } else {
            "".into()
        },
        if let Some(pf_time) = cfg.pf_time {
            format!("--pftime {}", pf_time)
        } else {
            "".into()
        },
        cfg.output_file.unwrap_or("/dev/null")
    )
    .cwd(cfg.exp_dir);

    let cmd = if cfg.allow_oom {
        cmd.allow_error()
    } else {
        cmd
    };

    shell.run(cmd)?;

    // Make sure memcached dies (this is needed for tools to stop recording and output data).
    shell.run(cmd!("memcached-tool localhost:11211"))?;
    shell.run(cmd!("memcached-tool localhost:11211 stats"))?;
    shell.run(cmd!("pkill memcached"))?;

    // Make sure perf is done.
    shell.run(cmd!(
        "while [[ $(pgrep perf) ]] ; do sleep 1 ; done ; echo done"
    ))?;

    Ok(())
}

/// Run the `memcached_gen_data` workload.
///
/// - `interval` is the interval at which to collect THP stats.
/// - `continual_compaction` specifies whether spurious failures are employed and what type.
/// - `output_file` is the file to which the workload will write its output; note that,
///   `cfg.output_file` is the file to which memcached request latency are written.
pub fn run_memcached_and_capture_thp<F>(
    shell: &SshShell,
    cfg: &MemcachedWorkloadConfig<'_, F>,
    interval: usize,
    continual_compaction: Option<usize>,
    output_file: &str,
) -> Result<(), failure::Error>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    // Start server
    start_memcached(&shell, cfg)?;

    // Turn on/off spurious failures
    if let Some(mode) = continual_compaction {
        shell.run(cmd!("echo {} | sudo tee /proc/compact_spurious_fail", mode))?;
    } else {
        shell.run(cmd!("echo 0 | sudo tee /proc/compact_spurious_fail"))?;
    }

    // Run workload
    let cmd = cmd!(
        "taskset -c {} ./target/release/memcached_and_capture_thp localhost:11211 {} {} {} {} | tee {}",
        cfg.client_pin_core,
        cfg.wk_size_gb,
        interval,
        cfg.output_file.unwrap_or("/dev/null"),
        if continual_compaction.is_some() {
            "--continual_compaction"
        } else {
            ""
        },
        output_file
    )
    .cwd(cfg.exp_dir)
    .use_bash();

    let cmd = if cfg.allow_oom {
        cmd.allow_error()
    } else {
        cmd
    };

    shell.run(cmd)?;

    Ok(())
}

/// The configuration of a MongoDB workload.
#[derive(Debug)]
pub struct MongoDBWorkloadConfig<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    /// The path of the bmks directory on the remote.
    pub bmks_dir: &'s str,
    /// The path of the database directory
    pub db_dir: &'s str,
    /// The size of the tmpfs in GB mounted at db_dir. If None, don't mount anything to
    /// db_dir
    pub tmpfs_size: Option<usize>,

    /// The cache size of `MongoDB` server in MB. The default will be used if None.
    pub cache_size_mb: Option<usize>,

    /// The core number that the `MongoDB` server is pinned to, if any.
    pub server_pin_core: Option<usize>,
    /// The core number that the workload client is pinned to.
    pub client_pin_core: usize,

    /// Indicates that we should run the workload under `perf` to capture MMU overhead stats.
    /// The string is the path to the output.
    pub mmu_perf: Option<(String, &'s [String])>,

    /// A callback executed after the mongodb server starts but before the workload starts.
    pub server_start_cb: F,
}

/// Start a `MongoDB` server in daemon mode with a given amount of memory for its
/// cache.
pub fn start_mongodb<F>(
    shell: &SshShell,
    cfg: &MongoDBWorkloadConfig<'_, F>,
) -> Result<(), failure::Error>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    let mongod_dir = format!("{}/mongo/build/opt/mongo", cfg.bmks_dir);

    let taskset = if let Some(server_pin_core) = cfg.server_pin_core {
        format!("taskset -c {} ", server_pin_core)
    } else {
        "".into()
    };

    let wired_tiger_cache_size = if let Some(cache_size_mb) = cfg.cache_size_mb {
        format!("--wiredTigerCacheSizeGB {}", cache_size_mb as f64 / 1024.0)
    } else {
        "".into()
    };

    // Create the DB directory if it doesn't exist and clear it.
    shell.run(cmd!("mkdir -p {}", cfg.db_dir))?;
    shell.run(cmd!("sudo rm -rf {}/*", cfg.db_dir))?;

    // See if we should mount a tmpfs to the DB directory
    if let Some(tmpfs_size) = cfg.tmpfs_size {
        shell.run(cmd!(
            "sudo mount -t tmpfs -o size={}g tmpfs {}",
            tmpfs_size,
            cfg.db_dir
        ))?;
    }

    // FIXME: The --fork flag might be a problem if something grabs the PID of
    // the first process, but not the forked process
    shell.run(
        cmd!(
            "sudo {} ./mongod --fork --logpath {}/log --dbpath {} {}",
            taskset,
            cfg.db_dir,
            cfg.db_dir,
            wired_tiger_cache_size,
        )
        .cwd(mongod_dir),
    )?;

    // Wait for the server to start
    while let Err(..) = shell.run(cmd!("nc -z localhost 27017")) {}

    // Run the callback.
    (cfg.server_start_cb)(shell)?;

    Ok(())
}

/// NAS Parallel Benchmark workload size classes. See online documentation.
pub enum NasClass {
    E,
    F,
}

/// Start the NAS CG workload. It must already be compiled. This workload takes a really long time,
/// so we start it in a spawned shell and return the join handle rather than waiting for the
/// workload to return.
///
/// - `zerosim_bmk_path` is the path to the `bmks` directory of `0sim-workspace`.
/// - `output_file` is the file to which the workload will write its output. If `None`, then
///   `/dev/null` is used.
/// - `eager` indicates whether the workload should be run with eager paging (only in VM); if so,
///   the path to Swapnil's scripts must be passed.
pub fn run_nas_cg(
    shell: &SshShell,
    zerosim_bmk_path: &str,
    class: NasClass,
    output_file: Option<&str>,
    eager: Option<&str>,
    tctx: &mut TasksetCtx,
) -> Result<SshSpawnHandle, failure::Error> {
    let class = match class {
        NasClass::E => "E",
        NasClass::F => "F",
    };

    if let Some(swapnil_path) = eager {
        setup_apriori_paging_process(shell, swapnil_path, &format!("cg.{}.x", class))?;
    }

    let handle = shell.spawn(
        cmd!(
            "taskset -c {} ./bin/cg.{}.x > {}",
            tctx.next(),
            class,
            output_file.unwrap_or("/dev/null")
        )
        .cwd(&format!("{}/NPB3.4/NPB3.4-OMP", zerosim_bmk_path)),
    )?;

    // Don't let the workload get OOM killed.
    oomkiller_blacklist_by_name(shell, &format!("cg.{}.x", class))?;

    Ok(handle)
}

bitflags! {
    pub struct MemhogOptions: u32 {
        /// Use pinned memory.
        const PIN = 1;

        /// Data-oblivious mode.
        const DATA_OBLIV = 1<<1;
    }
}

/// Run `memhog` on the remote.
///
/// - `exp_dir` is the path of the `numactl` benchmark directory.
/// - `r` is the number of times to call `memhog`, not the value of `-r`. `-r` is always passed a
///   value of `1`. If `None`, then run indefinitely.
/// - `size_kb` is the number of kilobytes to mmap and touch.
/// - `eager` indicates whether the workload should be run with eager paging (only in VM); if so,
///   the path to Swapnil's scripts must be passed.
pub fn run_memhog(
    shell: &SshShell,
    exp_dir: &str,
    r: Option<usize>,
    size_kb: usize,
    opts: MemhogOptions,
    eager: Option<&str>,
    tctx: &mut TasksetCtx,
) -> Result<SshSpawnHandle, SshError> {
    if let Some(swapnil_path) = eager {
        setup_apriori_paging_process(shell, swapnil_path, "memhog")?;
    }

    shell.spawn(cmd!(
        "{} ; do \
         LD_LIBRARY_PATH={} taskset -c {} {}/memhog -r1 {}k {} {} > /dev/null ; \
         done; \
         echo memhog done ;",
        if let Some(r) = r {
            format!("for i in `seq {}`", r)
        } else {
            "while [ 1 ]".into()
        },
        exp_dir,
        tctx.next(),
        exp_dir,
        size_kb,
        if opts.contains(MemhogOptions::PIN) {
            "-p"
        } else {
            ""
        },
        if opts.contains(MemhogOptions::DATA_OBLIV) {
            "-o"
        } else {
            ""
        },
    ))
}

/// Run the `time_loop` microbenchmark on the remote.
///
/// - `exp_dir` is the path of the 0sim-experiments submodule.
/// - `n` is the number of times to loop.
/// - `output_file` is the location to put the output.
/// - `eager` indicates whether the workload should be run with eager paging (only in VM); if so,
///   the path to Swapnil's scripts must be passed.
pub fn run_time_loop(
    shell: &SshShell,
    exp_dir: &str,
    n: usize,
    output_file: &str,
    eager: Option<&str>,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    if let Some(swapnil_path) = eager {
        setup_apriori_paging_process(shell, swapnil_path, "time_loop")?;
    }

    shell.run(
        cmd!(
            "sudo taskset -c {} ./target/release/time_loop {} > {}",
            tctx.next(),
            n,
            output_file
        )
        .cwd(exp_dir)
        .use_bash(),
    )?;

    Ok(())
}

/// Different modes for the `locality_mem_access` workload.
pub enum LocalityMemAccessMode {
    /// Local accesses. Good cache and TLB behavior.
    Local,

    /// Non-local accesses. Poor cache and TLB behavior.
    Random,
}

/// Settings for a single instance of the `locality_mem_access` workload.
pub struct LocalityMemAccessConfig<'s> {
    /// The path of the 0sim-experiments submodule.
    pub exp_dir: &'s str,

    /// Make local or non-local access patterns?
    pub locality: LocalityMemAccessMode,
    /// Number of accesses.
    pub n: usize,
    /// Turn on multithreading or not? And how many threads. Note that `None` is not the same as
    /// `Some(1)`, which has the main thread and 1 worker.
    pub threads: Option<usize>,

    /// The location to write the output for the workload.
    pub output_file: &'s str,

    /// Turn on eager paging. The path to Swapnil's scripts must be passed.
    pub eager: Option<&'s str>,
}

/// Run the `locality_mem_access` workload on the remote of the given number of iterations.
///
/// If `threads` is `None`, a single-threaded workload is run. Otherwise, a multithreaded workload
/// is run. The workload does its own CPU affinity assignments.
///
/// `eager` should only be used in a VM.
pub fn run_locality_mem_access(
    shell: &SshShell,
    cfg: &LocalityMemAccessConfig<'_>,
) -> Result<(), failure::Error> {
    let locality = match cfg.locality {
        LocalityMemAccessMode::Local => "-l",
        LocalityMemAccessMode::Random => "-n",
    };

    if let Some(swapnil_path) = cfg.eager {
        setup_apriori_paging_process(shell, swapnil_path, "locality_mem_access")?;
    }

    shell.run(
        cmd!(
            "time sudo ./target/release/locality_mem_access {} {} {} > {}",
            locality,
            cfg.n,
            if let Some(threads) = cfg.threads {
                format!("-t {}", threads)
            } else {
                "".into()
            },
            cfg.output_file,
        )
        .cwd(cfg.exp_dir)
        .use_bash(),
    )?;

    Ok(())
}

pub struct RedisWorkloadHandles {
    pub server_spawn_handle: SshSpawnHandle,
    pub client_spawn_handle: SshSpawnHandle,
}

impl RedisWorkloadHandles {
    pub fn wait_for_client(self) -> Result<(), failure::Error> {
        self.client_spawn_handle.join().1?;
        Ok(())
    }
}

/// Every setting of the redis workload.
#[derive(Debug)]
pub struct RedisWorkloadConfig<'s> {
    /// The path of the `0sim-experiments` submodule on the remote.
    pub exp_dir: &'s str,
    /// The path to the nullfs submodule on the remote.
    pub nullfs: &'s str,
    /// The path of the `redis.conf` file on the remote.
    pub redis_conf: &'s str,

    /// The size of `redis` server in MB.
    pub server_size_mb: usize,
    /// The size of the workload in GB.
    pub wk_size_gb: usize,
    /// The file to which the workload will write its output. If `None`, then `/dev/null` is used.
    pub output_file: Option<&'s str>,

    /// The core number that the redis server is pinned to, if any.
    pub server_pin_core: Option<usize>,
    /// The core number that the workload client is pinned to.
    pub client_pin_core: usize,

    /// The CPU frequency. If passed, the workload will use rdtsc for timing.
    pub freq: Option<usize>,
    /// Specifies the page fault time if TSC offsetting is to try to account for it.
    pub pf_time: Option<u64>,
    /// Indicates whether the workload should be run with eager paging. The path to Swapnil's
    /// scripts must be passed.
    pub eager: Option<&'s str>,

    /// Indicates that we should run the given pintool on the workload.
    pub pintool: Option<Pintool<'s>>,
}

/// Spawn a `redis` server in a new shell with the given amount of memory and set some important
/// config settings. Usually this is called indirectly through one of the other workload routines.
///
/// In order for redis snapshots to work properly, we need to tell the kernel to overcommit memory.
/// This requires `sudo` access.
///
/// We also
///     - delete any existing RDB files.
///     - set up a nullfs to use for the snapshot directory
///
/// `eager` should only be used in a VM.
///
/// Returns the spawned shell.
pub fn start_redis(
    shell: &SshShell,
    cfg: &RedisWorkloadConfig<'_>,
) -> Result<SshSpawnHandle, failure::Error> {
    // Set overcommit
    shell.run(cmd!("echo 1 | sudo tee /proc/sys/vm/overcommit_memory"))?;

    if let Some(swapnil_path) = cfg.eager {
        setup_apriori_paging_process(shell, swapnil_path, "redis-server")?;
    }

    // Delete any previous database
    shell.run(cmd!("rm -f /tmp/dump.rdb"))?;

    // Start nullfs
    shell.run(cmd!("sudo rm -rf /mnt/nullfs"))?;
    shell.run(cmd!("sudo mkdir -p /mnt/nullfs"))?;
    shell.run(cmd!("sudo chmod 777 /mnt/nullfs"))?;
    shell.run(cmd!("nohup {}/nullfs /mnt/nullfs", cfg.nullfs))?;

    // On some kernels, we need to do this again. On some, we don't.
    shell.run(cmd!("sudo chmod 777 /mnt/nullfs").allow_error())?;

    // Start the redis server
    let taskset = if let Some(server_pin_core) = cfg.server_pin_core {
        format!("taskset -c {} ", server_pin_core)
    } else {
        "".into()
    };

    let pintool = match cfg.pintool {
        Some(Pintool::MemTrace {
            pin_path,
            output_path,
        }) => format!(
            "{}/pin -t {}/source/tools/MemTrace/obj-intel64/membuffer.so -o {} -emit -- ",
            pin_path, pin_path, output_path
        ),

        None => "".into(),
    };

    let handle = shell.spawn(cmd!(
        "{}{}redis-server {}",
        pintool,
        taskset,
        cfg.redis_conf
    ))?;

    // Wait for server to start
    loop {
        let res = shell.run(cmd!("redis-cli -s /tmp/redis.sock INFO"));
        if res.is_ok() {
            break;
        }
    }

    const REDIS_SNAPSHOT_FREQ_SECS: usize = 300;

    // Settings
    // - maxmemory amount + evict random keys when full
    // - save snapshots every 300 seconds if >= 1 key changed to the file /tmp/dump.rdb
    with_shell! { shell =>
        cmd!("redis-cli -s /tmp/redis.sock CONFIG SET maxmemory-policy allkeys-random"),
        cmd!("redis-cli -s /tmp/redis.sock CONFIG SET maxmemory {}mb", cfg.server_size_mb),

        cmd!("redis-cli -s /tmp/redis.sock CONFIG SET save \"{} 1\"", REDIS_SNAPSHOT_FREQ_SECS),
    }

    // Make sure redis doesn't get oom killed.
    oomkiller_blacklist_by_name(shell, "redis-server")?;

    Ok(handle)
}

/// Run the `redis_gen_data` workload.
pub fn run_redis_gen_data(
    shell: &SshShell,
    cfg: &RedisWorkloadConfig<'_>,
) -> Result<RedisWorkloadHandles, failure::Error> {
    // Start server
    let server_spawn_handle = start_redis(&shell, cfg)?;

    // Run workload
    let client_spawn_handle = shell.spawn(
        cmd!(
            "taskset -c {} ./target/release/redis_gen_data unix:/tmp/redis.sock \
             {} {} {} | tee {} ; echo redis_gen_data done",
            cfg.client_pin_core,
            cfg.wk_size_gb,
            if let Some(freq) = cfg.freq {
                format!("--freq {}", freq)
            } else {
                "".into()
            },
            if let Some(pf_time) = cfg.pf_time {
                format!("--pftime {}", pf_time)
            } else {
                "".into()
            },
            cfg.output_file.unwrap_or("/dev/null")
        )
        .cwd(cfg.exp_dir),
    )?;

    Ok(RedisWorkloadHandles {
        server_spawn_handle,
        client_spawn_handle,
    })
}

/// Run the metis matrix multiply workload with the given matrix dimensions (square matrix). This
/// workload takes a really long time, so we start it in a spawned shell and return the join handle
/// rather than waiting for the workload to return.
///
/// NOTE: The amount of virtual memory used by the workload is `(dim * dim) * 4 * 2` bytes so if
/// you want a workload of size `t` GB, use `dim = sqrt(t << 27)`.
///
/// - `bmk_dir` is the path to the `Metis` directory in the workspace on the remote.
/// - `dim` is the dimension of the matrix (one side), which is assumed to be square.
/// - `eager` indicates whether the workload should be run with eager paging (only in VM); if so,
///   the path to Swapnil's scripts must be passed.
pub fn run_metis_matrix_mult(
    shell: &SshShell,
    bmk_dir: &str,
    dim: usize,
    eager: Option<&str>,
    tctx: &mut TasksetCtx,
) -> Result<SshSpawnHandle, SshError> {
    if let Some(swapnil_path) = eager {
        setup_apriori_paging_process(shell, swapnil_path, "matrix_mult2")?;
    }

    shell.spawn(
        cmd!(
            "taskset -c {} ./obj/matrix_mult2 -q -o -l {} ; echo matrix_mult2 done ;",
            tctx.next(),
            dim
        )
        .cwd(bmk_dir),
    )
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
///
/// - `exp_dir` is the path of the `0sim-experiments` submodule on the remote.
/// - `metis_dir` is the path to the `Metis` directory in the workspace on the remote.
/// - `numactl_dir` is the path to the `numactl` directory in the workspace on the remote.
/// - `redis_conf` is the path to the `redis.conf` file on the remote.
/// - `freq` is the _host_ CPU frequency in MHz.
/// - `size_gb` is the total amount of memory of the mix workload in GB.
/// - `eager` indicates whether the workload should be run with eager paging (only in VM); if so,
///   the path to Swapnil's scripts must be passed.
pub fn run_mix(
    shell: &SshShell,
    exp_dir: &str,
    metis_dir: &str,
    numactl_dir: &str,
    nullfs_dir: &str,
    redis_conf: &str,
    freq: usize,
    size_gb: usize,
    eager: Option<&str>,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    let redis_handles = run_redis_gen_data(
        shell,
        &RedisWorkloadConfig {
            exp_dir,
            nullfs: nullfs_dir,
            server_size_mb: (size_gb << 10) / 3,
            wk_size_gb: size_gb / 3,
            freq: Some(freq),
            pf_time: None,
            output_file: None,
            eager,
            client_pin_core: tctx.next(),
            server_pin_core: None,
            redis_conf,
            pintool: None,
        },
    )?;

    let matrix_dim = (((size_gb / 3) << 27) as f64).sqrt() as usize;
    let _metis_handle = run_metis_matrix_mult(shell, metis_dir, matrix_dim, eager, tctx)?;

    let _memhog_handles = run_memhog(
        shell,
        numactl_dir,
        None,
        (size_gb << 20) / 3,
        MemhogOptions::PIN | MemhogOptions::DATA_OBLIV,
        eager,
        tctx,
    )?;

    // Wait for redis client to finish
    redis_handles.client_spawn_handle.join().1?;

    Ok(())
}

/// Which YCSB core workload to run.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum YcsbWorkload {
    A,
    B,
    C,
    D,
    E,
    F,
    Custom {
        /// The number of entries to start the workload with
        record_count: usize,
        /// The number of operations to perform in the workload
        op_count: usize,
        /// The proportion of reads for the workload to perform
        read_prop: f32,
        /// The proportion of updates for the workload to perform
        update_prop: f32,
        /// The proportion of inserts for the workload to perform
        insert_prop: f32,
    },
}

/// Which backend to use for YCSB.
#[derive(Debug)]
pub enum YcsbSystem<'s, F>
where
    F: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    Memcached(MemcachedWorkloadConfig<'s, F>),
    Redis(RedisWorkloadConfig<'s>),
    MongoDB(MongoDBWorkloadConfig<'s, F>),
    KyotoCabinet,
}

/// Every setting of a YCSB workload.
pub struct YcsbConfig<'s, E, F, F2>
where
    E: std::error::Error + Sync + Send + 'static,
    F: Fn() -> Result<(), E>,
    F2: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    pub workload: YcsbWorkload,

    /// A config file for the server.
    ///
    /// For memcached and redis, the following config fields are ignored:
    /// - client_pin_core
    /// - wk_size_gb
    /// - output_file
    /// - freq
    /// - pf_time
    pub system: YcsbSystem<'s, F2>,

    /// The path of the YCSB directory.
    pub ycsb_path: &'s str,

    /// Path for the results file of the YCSB output
    pub ycsb_result_file: Option<&'s str>,

    /// A callback to run after the loading phase is complete.
    pub callback: F,
}

/// Run a YCSB workload, waiting to completion.
pub fn run_ycsb_workload<E, F, F2>(
    shell: &SshShell,
    cfg: YcsbConfig<E, F, F2>,
) -> Result<(), failure::Error>
where
    E: std::error::Error + Sync + Send + 'static,
    F: Fn() -> Result<(), E>,
    F2: for<'cb> Fn(&'cb SshShell) -> Result<(), failure::Error>,
{
    let user_home = get_user_home_dir(&shell)?;
    let ycsb_wkld_file = format!("{}/ycsb_wkld", user_home);
    let workload_file = match cfg.workload {
        YcsbWorkload::A => "workloads/workloada",
        YcsbWorkload::B => "workloads/workloadb",
        YcsbWorkload::C => "workloads/workloadc",
        YcsbWorkload::D => "workloads/workloadd",
        YcsbWorkload::E => "workloads/workloade",
        YcsbWorkload::F => "workloads/workloadf",
        YcsbWorkload::Custom { .. } => &ycsb_wkld_file,
    };
    let ycsb_result_file = cfg.ycsb_result_file.unwrap_or("");

    // If this is a custom workload, we have to build the workload file
    if let YcsbWorkload::Custom {
        record_count,
        op_count,
        read_prop,
        update_prop,
        insert_prop,
    } = cfg.workload
    {
        shell.run(cmd!(
            "echo \"recordcount={}\" > {}",
            record_count,
            ycsb_wkld_file
        ))?;
        shell.run(cmd!(
            "echo \"operationcount={}\" >> {}",
            op_count,
            ycsb_wkld_file
        ))?;
        shell.run(cmd!(
            "echo \"workload=site.ycsb.workloads.CoreWorkload\" >> {}",
            ycsb_wkld_file
        ))?;
        shell.run(cmd!("echo \"readallfields=true\" >> {}", ycsb_wkld_file))?;
        shell.run(cmd!(
            "echo \"readproportion={:.3}\" >> {}",
            read_prop,
            ycsb_wkld_file
        ))?;
        shell.run(cmd!(
            "echo \"updateproportion={:.3}\" >> {}",
            update_prop,
            ycsb_wkld_file
        ))?;
        shell.run(cmd!("echo \"scanproportion=0\" >> {}", ycsb_wkld_file))?;
        shell.run(cmd!(
            "echo \"insertproportion={:.3}\" >> {}",
            insert_prop,
            ycsb_wkld_file
        ))?;
        shell.run(cmd!(
            "echo \"requestdistribution=zipfian\" >> {}",
            ycsb_wkld_file
        ))?;
    }

    /// The number of KB a record takes.
    const RECORD_SIZE_KB: usize = 16;

    match &cfg.system {
        YcsbSystem::Memcached(cfg_memcached) => {
            // This is the number of records that would consume the memory given to memcached
            // (approximately)...
            let nrecords = (cfg_memcached.server_size_mb << 10) / RECORD_SIZE_KB;

            // ... however, the JVM for YCSB also consumes about 5-8% more memory (empirically),
            // so we make the workload a bit smaller to avoid being killed by the OOM killer.
            let nrecords = nrecords * 9 / 10;

            start_memcached(shell, &cfg_memcached)?;

            // recordcount is used for the "load" phase, while operationcount is used for the "run
            // phase. YCSB ignores the parameters in the alternate phases.
            let ycsb_flags = format!(
                "-p memcached.hosts=localhost:11211 -p recordcount={} -p operationcount={}",
                nrecords, nrecords
            );

            with_shell! { shell in &cfg.ycsb_path =>
                cmd!("./bin/ycsb load memcached -s -P {} {}", workload_file, ycsb_flags),
                cmd!("memcached-tool localhost:11211"),
            }

            // Run the callback before starting the next part.
            (cfg.callback)()?;

            with_shell! { shell in &cfg.ycsb_path =>
                cmd!("./bin/ycsb run memcached -s -P {} {} | tee {}", workload_file, ycsb_flags, ycsb_result_file),
            }
        }

        YcsbSystem::Redis(cfg_redis) => {
            // This is the number of records that would consume the memory given to redis
            // (approximately)...
            let nrecords = (cfg_redis.server_size_mb << 10) / RECORD_SIZE_KB;

            // ... however, the JVM for YCSB also consumes about 5-8% more memory (empirically),
            // so we make the workload a bit smaller to avoid being killed by the OOM killer.
            let nrecords = nrecords * 9 / 10;

            let _handle = start_redis(shell, &cfg_redis)?;

            // recordcount is used for the "load" phase, while operationcount is used for the "run
            // phase. YCSB ignores the parameters in the alternate phases.
            let ycsb_flags = format!(
                "-p redis.uds=/tmp/redis.sock -p recordcount={} -p operationcount={}",
                nrecords, nrecords
            );

            with_shell! { shell in &cfg.ycsb_path =>
                cmd!("./bin/ycsb load redis -s -P {} {}", workload_file, ycsb_flags),
                cmd!("redis-cli -s /tmp/redis.sock INFO"),
            }

            // Run the callback before starting the next part.
            (cfg.callback)()?;

            with_shell! { shell in &cfg.ycsb_path =>
                cmd!("./bin/ycsb run redis -s -P {} {} | tee {}", workload_file, ycsb_flags, ycsb_result_file),
            }
        }

        YcsbSystem::MongoDB(cfg_mongodb) => {
            start_mongodb(&shell, cfg_mongodb)?;

            // Load the database before starting the workload
            shell.run(
                cmd!("./bin/ycsb load mongodb -s -P {}", ycsb_wkld_file).cwd(&cfg.ycsb_path),
            )?;

            // Run the callback
            (cfg.callback)()?;

            // Start `perf` if needed.
            let perf_handle = if let Some((mmu_overhead_file, counters)) = &cfg_mongodb.mmu_perf {
                let handle = shell.spawn(cmd!(
                    "sudo perf stat -e {} -p `pgrep mongod` 2>&1 | tee {}",
                    counters.join(" -e "),
                    mmu_overhead_file
                ))?;

                // Wait for perf to start collection.
                shell.run(
                    cmd!("while [ ! -e {} ] ; do sleep 1 ; done", mmu_overhead_file).use_bash(),
                )?;

                Some(handle)
            } else {
                None
            };

            // Run workload
            shell.run(
                cmd!(
                    "./bin/ycsb run mongodb -s -P {} | tee {}",
                    ycsb_wkld_file,
                    ycsb_result_file
                )
                .cwd(&cfg.ycsb_path),
            )?;

            // Make sure mongod dies
            shell.run(cmd!("sudo pkill mongod"))?;

            // Make sure perf is done.
            if let Some(handle) = perf_handle {
                let (_, result) = handle.join();
                result?;
            }
        }

        YcsbSystem::KyotoCabinet => todo!("KC with memtracing support"),
    }

    Ok(())
}

/// Run the Graph500 workload (BFS and SSSP), waiting to completion.
pub fn run_graph500(
    shell: &SshShell,
    graph500_path: &str,
    scale: usize,
    output_file: &str,
    damon: Option<Damon>,
    pintool: Option<Pintool<'_>>,
) -> Result<(), failure::Error> {
    let damon = if let Some(damon) = damon {
        format!(
            "sudo {}/damo record -s {} -a {} -o {} -w -- ",
            damon.damon_path, damon.sample_interval, damon.aggregate_interval, damon.output_path,
        )
    } else {
        "".into()
    };

    let pintool = match pintool {
        Some(Pintool::MemTrace {
            pin_path,
            output_path,
        }) => format!(
            "{}/pin -t {}/source/tools/MemTrace/obj-intel64/membuffer.so -o {} -emit -ff -- ",
            pin_path, pin_path, output_path
        ),

        None => "".into(),
    };

    // Graph500 consists of 3 phases. The first phase generates the graph. It is not considered
    // part of the benchmark, but it takes a looong time. For memory tracing, we want to fast
    // forward past this part so as not to waste time and bloat the trace. To do this, the -ff flag
    // for the tracing PIN tool waits for `/tmp/pin-memtrace-go` to be created. Additionally, my
    // hacked-up version of graph500 will first create `/tmp/graph500-ready` then wait for
    // `/tmp/insinstrumentation-ready` ready to be created before proceeding.

    // Delete if they happen to already be there.
    shell.run(cmd!(
        "rm -f /tmp/instrumentation-ready /tmp/graph500-ready /tmp/pin-memtrace-go"
    ))?;

    // DAMON doesn't need to wait. Just let it go.
    if !damon.is_empty() {
        shell.run(cmd!("touch /tmp/instrumentation-ready"))?;
    }

    // Run the workload, possibly under instrumentation, but don't block.
    let handle = shell.spawn(cmd!(
        "{}{}{}/omp-csr/omp-csr -s {} | tee {}",
        damon,
        pintool,
        graph500_path,
        scale,
        output_file
    ))?;

    // Wait for the graph generation phase to complete. Then, inform any tooling and let the
    // benchmark continue.
    //shell.run(cmd!(
    //    "while [ ! -e /tmp/graph500-ready ] ; do sleep 1 ; done ; \
    //    touch /tmp/pin-memtrace-go ; \
    //    sleep 1 ; \
    //    touch /tmp/instrumentation-ready"
    //))?;

    // Wait for the workload to finish.
    let _out = handle.join();

    Ok(())
}

pub fn run_thp_ubmk(
    shell: &SshShell,
    size: usize,
    reps: usize,
    bmk_dir: &str,
    // The output file as well as a list of perf counters to record. Most processors can only
    // support 4-5 hardware counters, but you can do more software counters. To see the type of a
    // counter, use `perf list`.
    mmu_overhead: Option<(&str, &[String])>,
    perf_file: Option<&str>,
    pin_core: usize,
) -> Result<(), failure::Error> {
    // If reps is 0, omit the parameter
    let reps_str = if reps == 0 {
        "".to_string()
    } else {
        reps.to_string()
    };

    if let Some((mmu_overhead_file, counters)) = mmu_overhead {
        shell.run(
            cmd!(
                "sudo taskset -c {} \
                perf stat \
                -e {} \
                -D 65000 \
                -- ./ubmk {} {} 2>&1 | \
                tee {}",
                pin_core,
                counters.join(" -e "),
                size,
                reps_str,
                mmu_overhead_file
            )
            .cwd(bmk_dir),
        )?;
    } else if let Some(perf_file) = perf_file {
        shell.run(
            cmd!(
                "(sudo taskset -c {} ./ubmk {} 10000 &) && \
                 sudo perf record -a -C {} -g -F 99 -D 65000 sleep 180 && \
                 sudo pkill ubmk && \
                 sudo perf report --stdio > {} && \
                 echo DONE",
                pin_core,
                size,
                pin_core,
                perf_file,
            )
            .cwd(bmk_dir),
        )?;
    } else {
        shell
            .run(cmd!("sudo taskset -c {} ./ubmk {} {}", pin_core, size, reps_str).cwd(bmk_dir))?;
    }

    Ok(())
}

pub fn run_thp_ubmk_shm(
    shell: &SshShell,
    size: usize,
    reps: usize,
    use_huge_pages: bool,
    bmk_dir: &str,
    // The output file as well as a list of perf counters to record. Most processors can only
    // support 4-5 hardware counters, but you can do more software counters. To see the type of a
    // counter, use `perf list`.
    mmu_overhead: Option<(&str, &[String])>,
    perf_file: Option<&str>,
    pin_core: usize,
) -> Result<(), failure::Error> {
    // If reps is 0, omit the parameter
    let reps_str = if reps == 0 {
        "".to_string()
    } else {
        reps.to_string()
    };

    let use_huge_pages = if use_huge_pages { 1 } else { 0 };

    if let Some((mmu_overhead_file, counters)) = mmu_overhead {
        shell.run(
            cmd!(
                "sudo taskset -c {} \
                perf stat \
                -e {} \
                -D 5000 \
                -- ./ubmk-shm {} {} {} 2>&1 | \
                tee {}",
                pin_core,
                counters.join(" -e "),
                use_huge_pages,
                size,
                reps_str,
                mmu_overhead_file
            )
            .cwd(bmk_dir),
        )?;
    } else if let Some(perf_file) = perf_file {
        shell.run(
            cmd!(
                "(sudo taskset -c {} ./ubmk-shm {} {} 10000 &) && \
                 sudo perf record -a -C {} -g -F 99 -D 5000 sleep 180 && \
                 sudo pkill ubmk-shm && \
                 sudo perf report --stdio > {} && \
                 echo DONE",
                pin_core,
                use_huge_pages,
                size,
                pin_core,
                perf_file,
            )
            .cwd(bmk_dir),
        )?;
    } else {
        shell.run(
            cmd!(
                "sudo taskset -c {} ./ubmk-shm {} {} {}",
                pin_core,
                use_huge_pages,
                size,
                reps_str
            )
            .cwd(bmk_dir),
        )?;
    }

    Ok(())
}

/// Represents a single SPEC 2017 workload.
pub enum Spec2017Workload {
    Mcf,
    Xz { size: usize },
    Xalancbmk { size: usize },
}

pub fn run_hacky_spec17(
    shell: &SshShell,
    spec_dir: &str,
    workload: Spec2017Workload,
    mmu_overhead: Option<(&str, &[String])>,
    perf_file: Option<&str>,
    // The spec workloads default to 4 threads, so we require 4 cores.
    pin_cores: [usize; 4],
) -> Result<(), failure::Error> {
    const MCF_CMD: &str = "./mcf_s inp.in";
    const XZ_CMD: &str = "./xz_s cpu2006docs.tar.xz 6643 \
                          055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c\
                          774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa\
                          5ad2c04fbc447549c2810fae 1036078272 1111795472 4";
    const XALANCBMK_CMD: &str = "./xalancbmk_s -v input.xml xalanc.xsl > /dev/null";
    let user_home = &get_user_home_dir(&shell)?;

    let (cmd, bmk) = match workload {
        Spec2017Workload::Mcf => (MCF_CMD.to_string(), "mcf_s"),
        Spec2017Workload::Xz { size } => {
            // If size is 0, just use the default command otherwise use the custom one
            let cmd = if size == 0 {
                XZ_CMD.to_string()
            } else {
                spec17_xz_get_cmd_with_size(shell, size)?
            };
            (cmd, "xz_s")
        }
        Spec2017Workload::Xalancbmk { size: _ } => (XALANCBMK_CMD.to_string(), "xalancbmk_s"),
    };

    let bmk_dir = format!(
        "{}/benchspec/CPU/*{}/run/run_base_refspeed_markm-thp-m64.0000",
        spec_dir, bmk
    );

    // If this is the Xalanc benchmark, make sure it's using the right input file
    if let Spec2017Workload::Xalancbmk { size } = workload {
        // If size is 0, just use the default input file
        if size == 0 {
            shell.run(cmd!("cp t5.xml input.xml").cwd(&bmk_dir))?;
        } else {
            shell.run(
                cmd!(
                    "{}/0sim-workspace/bmks/spec2017/rand_xalanc_input.py {} > input.xml",
                    user_home,
                    size
                )
                .cwd(&bmk_dir),
            )?;
        }
    }

    let pin_cores = pin_cores
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    if let Some((mmu_overhead_file, counters)) = mmu_overhead {
        shell.run(
            cmd!(
                "sudo taskset -c {} \
                perf stat \
                -e {} \
                -o {} \
                -- {}",
                pin_cores,
                counters.join(" -e "),
                mmu_overhead_file,
                cmd,
            )
            .cwd(bmk_dir),
        )?;
    } else if let Some(perf_file) = perf_file {
        // TODO: not tested, should this be done sort of like thp_ubmk above?
        shell.run(
            cmd!(
                "sudo perf record -a -C {} -g -F 99 \
                 taskset -c {} {} && \
                 sudo perf report --stdio > {}",
                pin_cores,
                pin_cores,
                cmd,
                perf_file,
            )
            .cwd(bmk_dir),
        )?;
    } else {
        shell.run(cmd!("sudo taskset -c {} {}", pin_cores, cmd,).cwd(bmk_dir))?;
    }

    Ok(())
}

// size is the size of the data to perform the workload on in MB
fn spec17_xz_get_cmd_with_size(shell: &SshShell, size: usize) -> Result<String, failure::Error> {
    let user_home = &get_user_home_dir(&shell)?;
    let input_file = &dir!(user_home, "xz_input.tar.xz");
    let raw_input_file = &dir!(user_home, "xz_input.tar");
    // These directories add up to be about 25GB
    let constituent_dirs: Vec<String> = vec!["qemu-4.0.0", "parsec-3.0", "kernel-*"]
        .iter()
        .map(|&s| dir!(user_home, s))
        .collect();

    // If the input file does not exist, we have to create it
    let result = shell.run(cmd!("test -f {}", input_file));
    let create_input = match result {
        Err(e) => {
            // The file does not exist if test returns 1.
            // We can't handle any other error
            match e {
                SshError::NonZeroExit { cmd: _, exit } => {
                    if exit == 1 {
                        true
                    } else {
                        Err(e)?
                    }
                }
                _ => Err(e)?,
            }
        }
        Ok(_) => false,
    };

    if create_input {
        shell.run(cmd!(
            "tar cf {} {}",
            raw_input_file,
            constituent_dirs.join(" ")
        ))?;
        shell.run(cmd!("xz -4 < {} > {}", raw_input_file, input_file))?;
    }

    // Calculate the SHA 512 hash of the uncompressed input
    let output = shell.run(cmd!("sha512sum {}", raw_input_file))?.stdout;
    let mut output = output.split_whitespace();
    let hash = output.next().unwrap().trim().to_owned();

    // Construct the command
    let cmd = format!("./xz_s {} {} {} -1 -1 4", input_file, size, hash);

    Ok(cmd)
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum CannealWorkload {
    Small,
    Medium,
    Large,
    Native,
    Rand {
        size: usize,
        uniform_dist: bool,
        rand_num_inputs: bool,
    },
}

pub fn run_canneal(
    shell: &SshShell,
    workload: CannealWorkload,
    mmu_overhead: Option<(&str, &[String])>,
    perf_file: Option<&str>,
    pin_core: usize,
) -> Result<(), failure::Error> {
    const CANNEAL_PATH: &str = "parsec-3.0/pkgs/kernels/canneal/inst/amd64-linux.gcc/bin/";
    const CANNEAL_CMD: &str = "./canneal 1 15000 2000 input.nets 6000";
    const NET_PATH: &str = "parsec-3.0/pkgs/kernels/canneal/inputs/";

    // Extract the input file
    if let CannealWorkload::Rand {
        size,
        uniform_dist,
        rand_num_inputs,
    } = workload
    {
        shell.run(cmd!(
            "~/0sim-workspace/bmks/canneal/rand_canneal_input.py {} {} {} > {}/input.nets",
            size,
            if uniform_dist {
                "--dist_uniform"
            } else {
                "--dist_normal"
            },
            if rand_num_inputs {
                "--rand_num_inputs"
            } else {
                ""
            },
            CANNEAL_PATH
        ))?;
    } else {
        let input_file = match workload {
            CannealWorkload::Small => "input_simsmall.tar",
            CannealWorkload::Medium => "input_simmedium.tar",
            CannealWorkload::Large => "input_simlarge.tar",
            CannealWorkload::Native => "input_native.tar",
            _ => "error",
        };
        shell.run(cmd!("tar -xvf {}", input_file).cwd(NET_PATH))?;
        shell.run(cmd!("mv {}/*.nets {}/input.nets", NET_PATH, CANNEAL_PATH))?;
    }

    if let Some((mmu_overhead_file, counters)) = mmu_overhead {
        shell.run(
            cmd!(
                "sudo taskset -c {} \
                perf stat \
                -e {} \
                -- {} 2>&1 | \
                tee {}",
                pin_core,
                counters.join(" -e "),
                CANNEAL_CMD,
                mmu_overhead_file
            )
            .cwd(CANNEAL_PATH),
        )?;
    } else if let Some(perf_file) = perf_file {
        shell.run(
            cmd!(
                "sudo perf record -a -C {} -g -F 99 \
                taskset -c {} {} && \
                sudo perf report --stdio > {}",
                pin_core,
                pin_core,
                CANNEAL_CMD,
                perf_file,
            )
            .cwd(CANNEAL_PATH),
        )?;
    } else {
        shell.run(cmd!("sudo taskset -c {} {}", pin_core, CANNEAL_CMD).cwd(CANNEAL_PATH))?;
    }

    Ok(())
}
