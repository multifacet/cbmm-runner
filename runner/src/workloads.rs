//! Common workloads.

use bitflags::bitflags;

use serde::{Deserialize, Serialize};

use spurs::{
    cmd,
    ssh::{Execute, SshShell, SshSpawnHandle},
};

/// Set the apriori paging process using Swapnil's program. Requires `sudo`.
///
/// For example, to cause `ls` to be eagerly paged:
///
/// ```rust,ignore
/// setup_apriori_paging_process(&shell, "ls")?;
/// ```
pub fn setup_apriori_paging_process(shell: &SshShell, prog: &str) -> Result<(), failure::Error> {
    shell.run(cmd!(
        "{}/{}/apriori_paging_set_process {}",
        crate::common::paths::RESEARCH_WORKSPACE_PATH,
        crate::common::paths::ZEROSIM_SWAPNIL_PATH,
        prog
    ))?;
    Ok(())
}

/// Keeps track of which guest vCPUs have been assigned.
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

    /// Get the next core (wrapping around to 0 if all cores have been assigned).
    pub fn next(&mut self) -> usize {
        let c = self.next % self.ncores;
        self.next += 1;
        c
    }
}

/// The different patterns supported by the `time_mmap_touch` workload.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum TimeMmapTouchPattern {
    Zeros,
    Counter,
}

/// Run the `time_mmap_touch` workload on the remote `shell`. Requires `sudo`.
///
/// - `exp_dir` is the path of the `0sim-experiments` submodule on the remote.
/// - `pages` is the number of _pages_ to touch.
/// - `pattern` specifies the pattern to write to the pages.
/// - `prefault` specifies whether to prefault memory or not (true = yes).
/// - `pf_time` specifies the page fault time if TSC offsetting is to try to account for it.
/// - `output_file` is the file to which the workload will write its output. If `None`, then
///   `/dev/null` is used.
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_time_mmap_touch(
    shell: &SshShell,
    exp_dir: &str,
    pages: usize,
    pattern: TimeMmapTouchPattern,
    prefault: bool,
    pf_time: Option<u64>,
    output_file: Option<&str>,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    let pattern = match pattern {
        TimeMmapTouchPattern::Counter => "-c",
        TimeMmapTouchPattern::Zeros => "-z",
    };

    if eager {
        setup_apriori_paging_process(shell, "time_mmap_touch")?;
    }

    shell.run(
        cmd!(
            "sudo taskset -c {} ./target/release/time_mmap_touch {} {} {} {} > {}",
            tctx.next(),
            pages,
            pattern,
            if prefault { "-p" } else { "" },
            if let Some(pf_time) = pf_time {
                format!("--pftime {}", pf_time)
            } else {
                "".into()
            },
            output_file.unwrap_or("/dev/null")
        )
        .cwd(exp_dir)
        .use_bash(),
    )?;

    Ok(())
}

/// Start a `memcached` server in daemon mode as the given user with the given amount of memory.
/// Usually this is called indirectly through one of the other workload routines.
///
/// `allow_oom` specifies whether memcached is allowed to OOM. This gives much simpler performance
/// behaviors. memcached uses a large amount of the memory you give it for bookkeeping, rather
/// than user data, so OOM will almost certainly happen.
///
/// `eager` indicates whether the workload should be run with eager paging.
pub fn start_memcached(
    shell: &SshShell,
    size_mb: usize,
    user: &str,
    allow_oom: bool,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    if eager {
        setup_apriori_paging_process(shell, "memcached")?;
    }

    shell.run(cmd!(
        "taskset -c {} memcached {} -m {} -d -u {}",
        tctx.next(),
        if allow_oom { "-M" } else { "" },
        size_mb,
        user
    ))?;
    Ok(())
}

/// Run the `memcached_gen_data` workload.
///
/// - `user` is the user to run the `memcached` server as.
/// - `exp_dir` is the path of the `0sim-experiments` submodule on the remote.
/// - `server_size_mb` is the size of `memcached` server in MB.
/// - `wk_size_gb` is the size of the workload in GB.
/// - `freq` is the CPU frequency. If passed, the workload will use rdtsc for timing.
/// - `allow_oom` specifies whether the memcached server is allowed to OOM.
/// - `pf_time` specifies the page fault time if TSC offsetting is to try to account for it.
/// - `output_file` is the file to which the workload will write its output. If `None`, then
///   `/dev/null` is used.
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_memcached_gen_data(
    shell: &SshShell,
    user: &str,
    exp_dir: &str,
    server_size_mb: usize,
    wk_size_gb: usize,
    freq: Option<usize>,
    allow_oom: bool,
    pf_time: Option<u64>,
    output_file: Option<&str>,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    // Start server
    start_memcached(&shell, server_size_mb, user, allow_oom, eager, tctx)?;

    // Run workload
    let cmd = cmd!(
        "taskset -c {} ./target/release/memcached_gen_data localhost:11211 {} {} {} | tee {}",
        tctx.next(),
        wk_size_gb,
        if let Some(freq) = freq {
            format!("--freq {}", freq)
        } else {
            "".into()
        },
        if let Some(pf_time) = pf_time {
            format!("--pftime {}", pf_time)
        } else {
            "".into()
        },
        output_file.unwrap_or("/dev/null")
    )
    .cwd(exp_dir);

    let cmd = if allow_oom { cmd.allow_error() } else { cmd };

    shell.run(cmd)?;

    Ok(())
}

/// Run the `memcached_gen_data` workload.
///
/// - `user` is the user to run the `memcached` server as.
/// - `exp_dir` is the path of the `0sim-experiments` submodule on the remote.
/// - `server_size_mb` is the size of `memcached` server in MB.
/// - `wk_size_gb` is the size of the workload in GB.
/// - `interval` is the interval at which to collect THP stats.
/// - `allow_oom` specifies whether the memcached server is allowed to OOM.
/// - `continual_compaction` specifies whether spurious failures are employed and what type.
/// - `timing_file` is the file to which memcached request latencies will be written. If `None`,
///    then `/dev/null` is used.
/// - `output_file` is the file to which the workload will write its output.
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_memcached_and_capture_thp(
    shell: &SshShell,
    user: &str,
    exp_dir: &str,
    server_size_mb: usize,
    wk_size_gb: usize,
    interval: usize,
    allow_oom: bool,
    continual_compaction: Option<usize>,
    timing_file: Option<&str>,
    output_file: &str,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    // Start server
    start_memcached(&shell, server_size_mb, user, allow_oom, eager, tctx)?;

    // Turn on/off spurious failures
    if let Some(mode) = continual_compaction {
        shell.run(cmd!("echo {} | sudo tee /proc/compact_spurious_fail", mode))?;
    } else {
        shell.run(cmd!("echo 0 | sudo tee /proc/compact_spurious_fail"))?;
    }

    // Run workload
    let cmd = cmd!(
        "taskset -c {} ./target/release/memcached_and_capture_thp localhost:11211 {} {} {} {} | tee {}",
        tctx.next(),
        wk_size_gb,
        interval,
        timing_file.unwrap_or("/dev/null"),
        if continual_compaction.is_some() {
            "--continual_compaction"
        } else {
            ""
        },
        output_file
    )
    .cwd(exp_dir)
    .use_bash();

    let cmd = if allow_oom { cmd.allow_error() } else { cmd };

    shell.run(cmd)?;

    Ok(())
}

/// NAS Parallel Benchmark workload size classes. See online documentation.
pub enum NasClass {
    E,
}

/// Start the NAS CG workload. It must already be compiled. This workload takes a really long time,
/// so we start it in a spawned shell and return the join handle rather than waiting for the
/// workload to return.
///
/// - `zerosim_bmk_path` is the path to the `bmks` directory of `research-workspace`.
/// - `output_file` is the file to which the workload will write its output. If `None`, then
///   `/dev/null` is used.
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_nas_cg(
    shell: &SshShell,
    zerosim_bmk_path: &str,
    class: NasClass,
    output_file: Option<&str>,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(SshShell, SshSpawnHandle), failure::Error> {
    let class = match class {
        NasClass::E => "E",
    };

    if eager {
        setup_apriori_paging_process(shell, &format!("cg.{}.x", class))?;
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
/// - `r` is the number of times to call `memhog`, not the value of `-r`. `-r` is always passed
///   a value of `1`. If `None`, then run indefinitely.
/// - `size_kb` is the number of kilobytes to mmap and touch.
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_memhog(
    shell: &SshShell,
    r: Option<usize>,
    size_kb: usize,
    opts: MemhogOptions,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(SshShell, SshSpawnHandle), failure::Error> {
    if eager {
        setup_apriori_paging_process(shell, "memhog")?;
    }

    shell.spawn(cmd!(
        "{} ; do \
         taskset -c {} memhog -r1 {}k {} {} > /dev/null ; \
         done; \
         echo memhog done ;",
        tctx.next(),
        if let Some(r) = r {
            format!("for i in `seq {}`", r)
        } else {
            format!("while [ true ]")
        },
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
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_time_loop(
    shell: &SshShell,
    exp_dir: &str,
    n: usize,
    output_file: &str,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    if eager {
        setup_apriori_paging_process(shell, "time_loop")?;
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

/// Run the `locality_mem_access` workload on the remote.
pub fn run_locality_mem_access(
    shell: &SshShell,
    exp_dir: &str,
    locality: LocalityMemAccessMode,
    output_file: &str,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    let locality = match locality {
        LocalityMemAccessMode::Local => "-l",
        LocalityMemAccessMode::Random => "-n",
    };

    if eager {
        setup_apriori_paging_process(shell, "locality_mem_access")?;
    }

    shell.run(
        cmd!(
            "time sudo taskset -c {} ./target/release/locality_mem_access {} > {}",
            tctx.next(),
            locality,
            output_file,
        )
        .cwd(exp_dir)
        .use_bash(),
    )?;

    Ok(())
}

pub struct RedisWorkloadHandles {
    pub server_shell: SshShell,
    pub server_spawn_handle: SshSpawnHandle,
    pub client_shell: SshShell,
    pub client_spawn_handle: SshSpawnHandle,
}

impl RedisWorkloadHandles {
    pub fn wait_for_client(self) -> Result<(), failure::Error> {
        self.client_spawn_handle.join()?;
        Ok(())
    }
}

/// Spawn a `redis` server in a new shell with the given amount of memory and set some important
/// config settings. Usually this is called indirectly through one of the other workload routines.
///
/// In order for redis snapshots to work properly, we need to tell the kernel to overcommit memory.
/// This requires `sudo` access.
///
/// The redis server is listening at port 7777.
///
/// The caller should ensure that any previous RDB is deleted.
///
/// Returns the spawned shell.
pub fn start_redis(
    shell: &SshShell,
    size_mb: usize,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(SshShell, SshSpawnHandle), failure::Error> {
    // Set overcommit
    shell.run(cmd!("echo 1 | sudo tee /proc/sys/vm/overcommit_memory"))?;

    if eager {
        setup_apriori_paging_process(shell, "redis-server")?;
    }

    // Start the redis server
    let handle = shell.spawn(cmd!(
        "taskset -c {} redis-server --port 7777 --loglevel warning",
        tctx.next()
    ))?;

    // Wait for server to start
    loop {
        let res = shell.run(cmd!("redis-cli -p 7777 INFO"));
        if res.is_ok() {
            break;
        }
    }

    const REDIS_SNAPSHOT_FREQ_SECS: usize = 300;

    // Settings
    // - maxmemory amount + evict random keys when full
    // - save snapshots every 300 seconds if >= 1 key changed to the file /tmp/dump.rdb
    with_shell! { shell =>
        cmd!("redis-cli -p 7777 CONFIG SET maxmemory-policy allkeys-random"),
        cmd!("redis-cli -p 7777 CONFIG SET maxmemory {}mb", size_mb),

        cmd!("redis-cli -p 7777 CONFIG SET dir /tmp/"),
        cmd!("redis-cli -p 7777 CONFIG SET dbfilename dump.rdb"),
        cmd!("redis-cli -p 7777 CONFIG SET save \"{} 1\"", REDIS_SNAPSHOT_FREQ_SECS),
    }

    Ok(handle)
}

/// Run the `redis_gen_data` workload.
///
/// - `exp_dir` is the path of the `0sim-experiments` submodule on the remote.
/// - `server_size_mb` is the size of `redis` server in MB.
/// - `wk_size_gb` is the size of the workload in GB.
/// - `freq` is the CPU frequency. If passed, the workload will use rdtsc for timing.
/// - `pf_time` specifies the page fault time if TSC offsetting is to try to account for it.
/// - `output_file` is the file to which the workload will write its output. If `None`, then
///   `/dev/null` is used.
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_redis_gen_data(
    shell: &SshShell,
    exp_dir: &str,
    server_size_mb: usize,
    wk_size_gb: usize,
    freq: Option<usize>,
    pf_time: Option<u64>,
    output_file: Option<&str>,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<RedisWorkloadHandles, failure::Error> {
    // Start server
    let (server_shell, server_spawn_handle) = start_redis(&shell, server_size_mb, eager, tctx)?;

    // Run workload
    let (client_shell, client_spawn_handle) = shell.spawn(
        cmd!(
            "taskset -c {} ./target/release/redis_gen_data localhost:7777 {} {} {} | tee {} ; echo redis_gen_data done",
            tctx.next(),
            wk_size_gb,
            if let Some(freq) = freq {
                format!("--freq {}", freq)
            } else {
                "".into()
            },
            if let Some(pf_time) = pf_time {
                format!("--pftime {}", pf_time)
            } else {
                "".into()
            },
            output_file.unwrap_or("/dev/null")
        )
        .cwd(exp_dir),
    )?;

    Ok(RedisWorkloadHandles {
        server_shell,
        server_spawn_handle,
        client_shell,
        client_spawn_handle,
    })
}

/// Run the metis matrix multiply workload with the given matrix dimensions (square matrix). This
/// workload takes a really long time, so we start it in a spawned shell and return the join handle
/// rather than waiting for the workload to return.
///
/// NOTE: The amount of virtual memory used by the workload is
///
///     `(dim * dim) * 4 * 2` bytes
///
/// so if you want a workload of size `t` GB, use `dim = sqrt(t << 27)`.
///
/// - `bmk_dir` is the path to the `Metis` directory in the workspace on the remote.
/// - `dim` is the dimension of the matrix (one side), which is assumed to be square.
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_metis_matrix_mult(
    shell: &SshShell,
    bmk_dir: &str,
    dim: usize,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(SshShell, SshSpawnHandle), failure::Error> {
    if eager {
        setup_apriori_paging_process(shell, "matrix_mult2")?;
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
/// - `bmk_dir` is the path to the `Metis` directory in the workspace on the remote.
/// - `freq` is the _host_ CPU frequency in MHz.
/// - `size_gb` is the total amount of memory of the mix workload in GB.
/// - `eager` indicates whether the workload should be run with eager paging.
pub fn run_mix(
    shell: &SshShell,
    exp_dir: &str,
    bmk_dir: &str,
    freq: usize,
    size_gb: usize,
    eager: bool,
    tctx: &mut TasksetCtx,
) -> Result<(), failure::Error> {
    let redis_handles = run_redis_gen_data(
        shell,
        exp_dir,
        (size_gb << 10) / 3,
        size_gb / 3,
        Some(freq),
        /* pf_time */ None,
        /* output_file */ None,
        eager,
        tctx,
    )?;

    let matrix_dim = (((size_gb / 3) << 27) as f64).sqrt() as usize;
    let _metis_handle = run_metis_matrix_mult(shell, bmk_dir, matrix_dim, eager, tctx)?;

    let _memhog_handles = run_memhog(
        shell,
        None,
        (size_gb << 20) / 3,
        MemhogOptions::PIN | MemhogOptions::DATA_OBLIV,
        eager,
        tctx,
    )?;

    // Wait for redis client to finish
    redis_handles.client_spawn_handle.join()?;

    Ok(())
}
