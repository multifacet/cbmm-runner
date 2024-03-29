//! Run a workload on bare-metal (e.g. AWS).
//!
//! Requires `setup00000` with the appropriate kernel. If mmstats is passed, an instrumented kernel
//! needs to be installed. If `--damon` is used, then `setup00002` with the DAMON kernel is needed.
//! If `--thp_huge_addr` is used, then `setup00002` with an instrumented kernel is needed. If
//! `--hawkeye` is used, then `setup00004` is needed to install hawkeye and related tools.

use std::{collections::HashMap, fs, time::Duration};

use clap::clap_app;

use crate::{
    background::{BackgroundContext, BackgroundTask},
    cli::{damon, memtrace, validator},
    cpu::{cpu_family_model, IntelX86Model, Processor},
    dir,
    exp_0sim::*,
    get_cpu_freq, get_user_home_dir,
    output::{Parametrize, Timestamp},
    paths::*,
    time,
    workloads::{
        gen_cb_wrapper_command_prefix, gen_perf_command_prefix, run_canneal, run_graph500,
        run_hacky_spec17, run_locality_mem_access, run_memcached_gen_data, run_redis_gen_data,
        run_thp_ubmk, run_thp_ubmk_shm, run_time_loop, run_time_mmap_touch,
        setup_apriori_paging_processes, spawn_nas_cg, start_redis, CannealWorkload, Damon,
        LocalityMemAccessConfig, LocalityMemAccessMode, MemcachedWorkloadConfig,
        MongoDBWorkloadConfig, NasClass, Pintool, RedisWorkloadConfig, Spec2017Workload,
        TasksetCtx, TimeMmapTouchConfig, TimeMmapTouchPattern, YcsbConfig, YcsbSession, YcsbSystem,
        YcsbWorkload,
    },
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};
use spurs_util::escape_for_bash;

pub const PERIOD: usize = 10; // seconds

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
enum Workload {
    TimeLoop {
        n: usize,
    },
    LocalityMemAccess {
        n: usize,
    },
    TimeMmapTouch {
        size: usize,
        pattern: TimeMmapTouchPattern,
    },
    ThpUbmk {
        size: usize,
        reps: usize,
    },
    ThpUbmkShm {
        size: usize,
        reps: usize,
    },
    Memcached {
        size: usize,
    },
    MemcachedYcsb {
        size: usize,
        op_count: usize,
        read_prop: f32,
        update_prop: f32,
    },
    Redis {
        size: usize,
        nullfs: bool,
    },
    RedisYcsb {
        size: usize,
        nullfs: bool,
        op_count: usize,
        read_prop: f32,
        update_prop: f32,
    },
    MongoDB {
        op_count: usize,
        read_prop: f32,
        update_prop: f32,
        tmpfs_size: Option<usize>,
        cache_size: Option<usize>,
    },
    Graph500 {
        scale: usize,
    },
    Spec2017Mcf,
    Spec2017Xalancbmk {
        size: usize,
    },
    Spec2017Xz {
        spec_input: bool,
        size: usize,
    },
    Canneal {
        workload: CannealWorkload,
    },
    NasCG {
        class: NasClass,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThpHugeAddrMode {
    Equal {
        addr: u64,
    },
    Greater {
        addr: u64,
    },
    Less {
        addr: u64,
    },

    /// A list of ranges as tuples: (start, end), where start is inclusive and end is exclusive.
    Ranges {
        ranges: Vec<(u64, u64)>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThpHugeAddrProcess {
    /// Use for processes that have already started.
    Pid(usize),

    /// Use for processes that have not started yet.
    Command(String),
}

impl ThpHugeAddrProcess {
    pub fn from_name<S: AsRef<str>>(name: S) -> Self {
        // We need to truncate the name to 15 characters because Linux will truncate current->comm
        // to 15 characters. In order for them to match we truncate it here...
        ThpHugeAddrProcess::Command(name.as_ref().get(..15).unwrap_or(name.as_ref()).to_owned())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    workload: Workload,

    #[name(self.eager)]
    eager: bool,

    #[name(self.fragmentation.is_some())]
    fragmentation: Option<usize>,

    #[name(self.transparent_hugepage_enabled == "never")]
    transparent_hugepage_enabled: String,
    transparent_hugepage_defrag: String,
    transparent_hugepage_khugepaged_defrag: usize,
    transparent_hugepage_khugepaged_alloc_sleep_ms: usize,
    transparent_hugepage_khugepaged_scan_sleep_ms: usize,
    #[name(self.transparent_hugepage_huge_addr.is_some())]
    transparent_hugepage_huge_addr: Option<ThpHugeAddrMode>,

    mmstats: bool,
    meminfo_periodic: bool,
    damon: bool,
    damon_sample_interval: usize,
    damon_aggr_interval: usize,
    memtrace: bool,
    mmu_overhead: bool,
    perf_record: bool,
    perf_counters: Vec<String>,
    smaps_periodic: bool,
    mmap_tracker: bool,
    kbadgerd: bool,
    kbadgerd_sleep_interval: Option<usize>,
    mm_econ: bool,
    mm_econ_benefit_file: Option<String>,
    enable_aslr: bool,
    pftrace: Option<usize>,
    bpf_pftrace: Option<usize>,
    asynczero: bool,
    hawkeye: bool,
    eagerprofile: Option<usize>,

    username: String,
    host: String,

    local_git_hash: String,
    remote_git_hash: String,

    remote_research_settings: std::collections::BTreeMap<String, String>,

    #[timestamp]
    timestamp: Timestamp,
}

pub fn cli_options() -> clap::App<'static, 'static> {
    let app = clap_app! { exp00010 =>
        (about: "Run experiment 00010. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")
        (@subcommand time_loop =>
            (about: "Run the `time_loop` workload.")
            (@arg N: +required +takes_value {validator::is::<usize>}
             "The number of iterations of the workload (e.g. 50000000), preferably \
              divisible by 8 for `locality_mem_access`")
            )
        (@subcommand locality_mem_access =>
            (about: "Run the `locality_mem_access` workload.")
            (@arg N: +required +takes_value {validator::is::<usize>}
             "The number of iterations of the workload (e.g. 50000000), preferably \
              divisible by 8 for `locality_mem_access`")
        )
        (@subcommand time_mmap_touch =>
            (about: "Run the `time_mmap_touch` workload.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload (e.g. 500)")
            (@group PATTERN =>
                (@attributes +required)
                (@arg zeros: -z "Fill pages with zeros")
                (@arg counter: -c "Fill pages with counter values")
            )
        )
        (@subcommand thp_ubmk =>
            (about: "Run a ubmk that benefits greatly from THP")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload (e.g. 100)")
            (@arg REPS: +takes_value {validator::is::<usize>}
             "The number of reps the workload should run (e.g. 50)")
        )
        (@subcommand thp_ubmk_shm =>
            (about: "Run a ubmk that benefits greatly from THP but uses \
                     shared memory to avoid store buffer bottlenecks.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload (e.g. 100)")
            (@arg REPS: +takes_value {validator::is::<usize>}
             "The number of reps the workload should run (e.g. 50)")
        )
        (@subcommand memcached =>
            (about: "Run the `memcached` workload using the memcached_gen_data driver.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload (e.g. 500)")
        )
        (@subcommand memcachedycsb =>
            (about: "Run the `memcached` workload using the YCSB driver.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload (e.g. 500)")
            (@arg OP_COUNT: --op_count +takes_value {validator::is::<usize>}
             "The number of operations to perform during the workload.\
             The default is 1000.")
            (@arg READ_PROP: --read_prop +takes_value {validator::is::<f32>}
             "The proportion of read operations to perform as a value between 0 and 1.\
             The default is 0.5. The proportion on insert operations will be 1 - read_prop - update_prop.")
            (@arg UPDATE_PROP: --update_prop +takes_value {validator::is::<f32>}
             "The proportion of read operations to perform as a value between 0 and 1.\
             The default is 0.5. The proportion on insert operations will be 1 - read_prop - update_prop")
        )
        (@subcommand redis =>
            (about: "Run the `redis` workload using the redis_gen_data driver.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload")
            (@arg NULLFS: --nullfs
             "Write the redis snapshot to a nullfs")
        )
        (@subcommand redisycsb =>
            (about: "Run the `redis` workload using the YCSB driver.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload")
            (@arg NULLFS: --nullfs
             "Write the redis snapshot to a nullfs")
            (@arg OP_COUNT: --op_count +takes_value {validator::is::<usize>}
             "The number of operations to perform during the workload.\
             The default is 1000.")
            (@arg READ_PROP: --read_prop +takes_value {validator::is::<f32>}
             "The proportion of read operations to perform as a value between 0 and 1.\
             The default is 0.5. The proportion on insert operations will be 1 - read_prop - update_prop.")
            (@arg UPDATE_PROP: --update_prop +takes_value {validator::is::<f32>}
             "The proportion of read operations to perform as a value between 0 and 1.\
             The default is 0.5. The proportion on insert operations will be 1 - read_prop - update_prop")
        )
        (@subcommand mongodb =>
            (about: "Run the MongoDB workload.")
            (@arg OP_COUNT: --op_count +takes_value {validator::is::<usize>}
             "The number of operations to perform during the workload.\
             The default is 1000.")
            (@arg READ_PROP: --read_prop +takes_value {validator::is::<f32>}
             "The proportion of read operations to perform as a value between 0 and 1.\
             The default is 0.5. The proportion on insert operations will be 1 - read_prop - update_prop.")
            (@arg UPDATE_PROP: --update_prop +takes_value {validator::is::<f32>}
             "The proportion of read operations to perform as a value between 0 and 1.\
             The default is 0.5. The proportion on insert operations will be 1 - read_prop - update_prop")
            (@arg TMPFS_SIZE: --tmpfs_size + takes_value {validator::is::<usize>}
             "Place the MongoDB database in a tmpfs of the specified size in GB.")
            (@arg CACHE_SIZE: --cache_size + takes_value {validator::is::<usize>}
             "The size in GB of MongoDB's in memory cache")
        )
        (@subcommand graph500 =>
            (about: "Run the graph500 workload (all kernels).")
            (@arg SCALE: +required +takes_value {validator::is::<usize>}
             "log(vertices) for the workload (e.g. 29). See graph500 website for more info.")
        )
        (@subcommand hacky_spec17 =>
            (about: "A quick and dirty hack to run a spec workload on cloudlab")
            (@arg WHICH: +required
             "Which spec workload to run.")
            (@arg SIZE: --spec_size +takes_value {validator::is::<usize>}
             "The size of the spec workload input.")
            (@arg SPEC_INPUT: --input +takes_value
             "Use the given SPEC input for the workload.")
        )
        (@subcommand canneal =>
            (about: "Run the canneal workload.")
            (@group CANNEAL_WORKLOAD =>
                (@arg SMALL: --small
                 "Use the small workload.")
                (@arg MEDIUM: --medium
                 "Use the medium workload.")
                (@arg LARGE: --large
                 "Use the large workload.")
                (@arg NATIVE: --native
                 "Use the native workload (default).")
                (@arg RAND: --rand +takes_value {validator::is::<usize>}
                 "Generate a random workload with a specified number of nets.")
             )
             (@group RAND_DIST =>
                (@arg DIST_UNIFORM: --dist_uniform requires[RAND]
                 "Use a uniform distribution to generate the canneal input file.")
                (@arg DIST_NORMAL: --dist_normal requires[RAND]
                 "Use a normal distribution to generate the canneal input file.")
             )
             (@arg SEED: --seed requires[RAND] +takes_value {validator::is::<usize>}
              "Seed used to generate input file")
        )
        (@subcommand nascg =>
            (about: "Run NAS Parallel Benchmark CG")
            (@group CLASS =>
                (@attributes +required)
                (@arg D: --d "Run class D")
                (@arg E: --e "Run class E")
                (@arg F: --f "Run class F")
            )
        )
        (@arg EAGER: --eager
         "(optional) Use eager paging; requires a kernel that has eager paging.")
        (@arg MMSTATS: --memstats
         "(optional) Collect latency histograms for memory management ops; \
          requires a kernel that has instrumentation.")
        (@arg MEMINFO_PERIODIC: --meminfo_periodic
         "Collect /proc/meminfo data periodically.")
        (@arg MMU_OVERHEAD: --mmu_overhead
         "Collect MMU overhead stats via perf counters.")
        (@group THP_SETTINGS =>
            (@arg DISABLE_THP: --disable_thp
             "Disable THP completely.")
            (@arg THP_HUGE_ADDR: --thp_huge_addr +takes_value {is_huge_page_addr_hex}
             "Set the THP huge_addr setting to the given value and disable THP for other memory.")
            (@arg THP_HUGE_ADDR_RANGES: --thp_huge_addr_ranges
             {is_huge_page_addr_hex} +takes_value ...
             "Make all pages in the given range(s) huge. Pass values as space-separated integers \
              in hex a decimal: START END START END ..., where START is inclusive, and END is \
              exclusive.")
        )
        (@arg THP_HUGE_ADDR_LE: --thp_huge_addr_le
            requires[THP_HUGE_ADDR] conflicts_with[THP_HUGE_ADDR_GE]
            "Make all pages <=THP_HUGE_ADDR huge.")
        (@arg THP_HUGE_ADDR_GE: --thp_huge_addr_ge
            requires[THP_HUGE_ADDR] conflicts_with[THP_HUGE_ADDR_LE]
            "Make all pages >=THP_HUGE_ADDR huge.")
        (@arg PERF_RECORD: --perf_record
         "Measure the workload using perf record.")
        (@arg PERF_COUNTER: --perf_counter +takes_value ... number_of_values(1)
         "Collect the given counters instead of the default ones.")
        (@arg SMAPS_PERIODIC: --smaps_periodic
         "Collect /proc/[PID]/smaps data periodically for the main workload process.")
        (@arg MMAP_TRACKER: --mmap_tracker
         "Record stats for mmap calls for the main workload process.")
        (@arg KBADGERD: --kbadgerd
         "Use kbadgerd to measure TLB misses.")
        (@arg KBADGERD_SLEEP_INTERVAL: --kbadgerd_sleep_interval
         +takes_value {validator::is::<usize>} requires[KBADGERD]
         "Sets the sleep_interval for kbadgerd.")
        (@arg MM_ECON: --mm_econ
         "Enable mm_econ.")
        (@arg MM_ECON_BENEFIT_FILE: --mm_econ_benefit_file +takes_value
         requires[MM_ECON]
         "Set a benefits file for the workload process if there is an obvious choice. The file \
          should contain a list of mmap filters in the form of a CSV file. The file should have the \
          format:\n\
          SECTION,MISSES,CONSTRAINTS\n\
          where SECTION can be code, data, heap, or mmap,\n\
          CONSTRAINTS is an unbounded list of QUANTITY,COMP,VALUE\n\
          QUANTITY can be section_off, addr, len, prot, flags, fd, or off\n\
          COMP can be >, <, or =.")
        (@arg ENABLE_ASLR: --enable_aslr
         "Enable ASLR.")
        (@arg PFTRACE: --pftrace
         "Enable page fault tracing (requires an instrumented kernel).")
        (@arg BPFPFTRACE: --bpf_pftrace
         "Enable page fault tracing via BPF.")
        (@arg PFTRACE_THRESHOLD: --pftrace_threshold
         +takes_value {validator::is::<usize>} requires[PFTRACE]
         "Sets the pftrace_threshold for minimum latency to be sampled (in cycles!).")
        (@arg BPF_PFTRACE_THRESHOLD: --bpf_pftrace_threshold
         +takes_value {validator::is::<usize>} requires[BPFPFTRACE]
         "Sets the pftrace_threshold for minimum latency to be sampled (in nanoseconds!).")
        (@arg ASYNCZERO: --asynczero
         "Enable async pre-zeroing.")
        (@arg HAWKEYE: --hawkeye
         conflicts_with[MM_ECON KBADGERD THP_HUGE_ADDR PFTRACE EAGER MMSTATS]
         "Turn on HawkEye (ASPLOS '19).")
        (@arg FRAGMENTATION: --fragmentation +takes_value {validator::is::<usize>}
         "Fragment the given percentage of memory. Must be an integer between 0 and 100. \
          This will consume a bit of memory, as there is a daemon that holds on to a bit \
          of memory to fragment it.")
        (@arg EAGERPROFILE: --eagerprofile +takes_value {validator::is::<usize>}
         "Recorded pagemap info at the given interval (in seconds) for the workload.")
        (@arg TERM: --end ...
         "Used to signal the cli parser that a list of items has ended.")
    };

    let app = damon::add_cli_options(app);
    let app = memtrace::add_cli_options(app);

    app
}

/// Check that the given string is a 2M-aligned address in hex with or without leading 0x.
fn is_huge_page_addr_hex(s: String) -> Result<(), String> {
    let without_prefix = s.trim_start_matches("0x");
    let val = u64::from_str_radix(without_prefix, 16).map_err(|err| format!("{}", err))?;
    if val % (2 << 20) == 0 {
        Ok(())
    } else {
        Err("Huge page address is not 2MB-aligned.".into())
    }
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let workload = match sub_m.subcommand() {
        ("time_loop", Some(sub_m)) => {
            let n = sub_m.value_of("N").unwrap().parse::<usize>().unwrap();
            Workload::TimeLoop { n }
        }

        ("locality_mem_access", Some(sub_m)) => {
            let n = sub_m.value_of("N").unwrap().parse::<usize>().unwrap();
            Workload::LocalityMemAccess { n }
        }

        ("time_mmap_touch", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();

            let pattern = if sub_m.is_present("zeros") {
                TimeMmapTouchPattern::Zeros
            } else {
                TimeMmapTouchPattern::Counter
            };

            Workload::TimeMmapTouch { size, pattern }
        }

        ("thp_ubmk", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();
            let reps = sub_m
                .value_of("REPS")
                .unwrap_or("0")
                .parse::<usize>()
                .unwrap();

            Workload::ThpUbmk { size, reps }
        }

        ("thp_ubmk_shm", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();
            let reps = sub_m
                .value_of("REPS")
                .unwrap_or("0")
                .parse::<usize>()
                .unwrap();

            Workload::ThpUbmkShm { size, reps }
        }

        ("memcached", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();

            Workload::Memcached { size }
        }

        ("memcachedycsb", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();
            let op_count = sub_m
                .value_of("OP_COUNT")
                .unwrap_or("1000")
                .parse::<usize>()
                .unwrap();
            let read_prop = sub_m
                .value_of("READ_PROP")
                .unwrap_or("0.5")
                .parse::<f32>()
                .unwrap();
            let update_prop = sub_m
                .value_of("UPDATE_PROP")
                .unwrap_or("0.5")
                .parse::<f32>()
                .unwrap();

            Workload::MemcachedYcsb {
                size,
                op_count,
                read_prop,
                update_prop,
            }
        }

        ("redis", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();
            let nullfs = sub_m.is_present("NULLFS");

            Workload::Redis { size, nullfs }
        }

        ("redisycsb", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();
            let nullfs = sub_m.is_present("NULLFS");
            let op_count = sub_m
                .value_of("OP_COUNT")
                .unwrap_or("1000")
                .parse::<usize>()
                .unwrap();
            let read_prop = sub_m
                .value_of("READ_PROP")
                .unwrap_or("0.5")
                .parse::<f32>()
                .unwrap();
            let update_prop = sub_m
                .value_of("UPDATE_PROP")
                .unwrap_or("0.5")
                .parse::<f32>()
                .unwrap();

            Workload::RedisYcsb {
                size,
                nullfs,
                op_count,
                read_prop,
                update_prop,
            }
        }

        ("mongodb", Some(sub_m)) => {
            let op_count = sub_m
                .value_of("OP_COUNT")
                .unwrap_or("1000")
                .parse::<usize>()
                .unwrap();
            let read_prop = sub_m
                .value_of("READ_PROP")
                .unwrap_or("0.5")
                .parse::<f32>()
                .unwrap();
            let update_prop = sub_m
                .value_of("UPDATE_PROP")
                .unwrap_or("0.5")
                .parse::<f32>()
                .unwrap();
            let tmpfs_size = if let Some(size) = sub_m.value_of("TMPFS_SIZE") {
                Some(size.parse::<usize>().unwrap())
            } else {
                None
            };
            let cache_size = if let Some(size) = sub_m.value_of("CACHE_SIZE") {
                // The command line arg is in GB and MongoDB wants it in MB
                Some(size.parse::<usize>().unwrap() * 1024)
            } else {
                None
            };

            if read_prop > 1.0 || read_prop < 0.0 {
                panic!("--read_prop must be between 0 and 1.");
            }
            if update_prop > 1.0 || update_prop < 0.0 {
                panic!("--update_prop must be between 0 and 1.");
            }
            if (read_prop + update_prop) > 1.0 {
                panic!("The sum of --read_prop and --update_prop must not be greater than 1.");
            }

            Workload::MongoDB {
                op_count,
                read_prop,
                update_prop,
                tmpfs_size,
                cache_size,
            }
        }

        ("graph500", Some(sub_m)) => {
            let scale = sub_m.value_of("SCALE").unwrap().parse::<usize>().unwrap();

            Workload::Graph500 { scale }
        }

        ("hacky_spec17", Some(sub_m)) => {
            let size = sub_m
                .value_of("SIZE")
                .unwrap_or("0")
                .parse::<usize>()
                .unwrap();
            let spec_input = sub_m.value_of("SPEC_INPUT").unwrap_or("testing");
            let spec_input = spec_input == "training";

            let wk = match sub_m.value_of("WHICH").unwrap() {
                "mcf" => Workload::Spec2017Mcf,
                "xalancbmk" => Workload::Spec2017Xalancbmk { size },
                "xz" => Workload::Spec2017Xz { spec_input, size },
                _ => panic!("Unknown spec workload"),
            };

            if size != 0 {
                let size_implemented = match &wk {
                    Workload::Spec2017Xz {
                        spec_input: _,
                        size: _,
                    } => true,
                    Workload::Spec2017Xalancbmk { size: _ } => true,
                    _ => false,
                };

                if !size_implemented {
                    unimplemented!(
                        "the --spec_size flag is not implemented for the chosen workload"
                    );
                }
            }

            wk
        }

        ("canneal", Some(sub_m)) => {
            let workload = if sub_m.is_present("SMALL") {
                CannealWorkload::Small
            } else if sub_m.is_present("MEDIUM") {
                CannealWorkload::Medium
            } else if sub_m.is_present("LARGE") {
                CannealWorkload::Large
            } else if sub_m.is_present("RAND") {
                let size = sub_m.value_of("RAND").unwrap().parse::<usize>().unwrap();
                let uniform_dist = if sub_m.is_present("DIST_NORMAL") {
                    false
                } else {
                    true
                };
                let seed = sub_m.value_of("SEED").map(|s| s.parse::<usize>().unwrap());
                CannealWorkload::Rand {
                    size,
                    uniform_dist,
                    seed,
                }
            } else {
                CannealWorkload::Native
            };

            Workload::Canneal { workload }
        }

        ("nascg", Some(sub_m)) => {
            let class = if sub_m.is_present("D") {
                NasClass::D
            } else if sub_m.is_present("E") {
                NasClass::E
            } else if sub_m.is_present("F") {
                NasClass::F
            } else {
                unreachable!()
            };

            Workload::NasCG { class }
        }

        _ => unreachable!(),
    };

    let eager = sub_m.is_present("EAGER");
    let mmstats = sub_m.is_present("MMSTATS");
    let meminfo_periodic = sub_m.is_present("MEMINFO_PERIODIC");
    let (damon, damon_sample_interval, damon_aggr_interval) = damon::parse_cli_options(sub_m);
    let memtrace = memtrace::parse_cli_options(sub_m);
    let mmu_overhead = sub_m.is_present("MMU_OVERHEAD");
    let perf_record = sub_m.is_present("PERF_RECORD");
    let smaps_periodic = sub_m.is_present("SMAPS_PERIODIC");
    let mmap_tracker = sub_m.is_present("MMAP_TRACKER");
    let kbadgerd = sub_m.is_present("KBADGERD");
    let kbadgerd_sleep_interval = sub_m
        .value_of("KBADGERD_SLEEP_INTERVAL")
        .map(|s| s.parse::<usize>().unwrap());
    let mm_econ = sub_m.is_present("MM_ECON");
    let mm_econ_benefit_file = sub_m.value_of("MM_ECON_BENEFIT_FILE").map(|s| s.to_owned());
    let enable_aslr = sub_m.is_present("ENABLE_ASLR");
    let pftrace = sub_m.is_present("PFTRACE").then(|| {
        sub_m
            .value_of("PFTRACE_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap())
            .unwrap_or(100000)
    });
    let bpf_pftrace = sub_m.is_present("BPFPFTRACE").then(|| {
        sub_m
            .value_of("BPF_PFTRACE_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap())
            .unwrap_or(38461) // ~100k cycles at 2600MHz
    });
    let asynczero = sub_m.is_present("ASYNCZERO");
    let hawkeye = sub_m.is_present("HAWKEYE");
    let fragmentation = sub_m
        .value_of("FRAGMENTATION")
        .map(|s| s.parse::<usize>().unwrap());

    // FIXME: thp_ubmk_shm doesn't support thp_huge_addr at the moment. It's possible to implement
    // it, but I haven't yet... The implementation would look as follows: thp_ubmk_shm would take
    // an argument for which pages to use huge pages, and it would map those backed by the
    // hugetlbfs. The remaining pages would be backed by normal shm.
    if let Workload::ThpUbmkShm { .. } = workload {
        if sub_m.is_present("THP_UBMK_DIR") {
            unimplemented!("thp_huge_addr isn't supported by thp_ubmk_shm yet.");
        }
    }
    let eagerprofile = sub_m
        .value_of("EAGERPROFILE")
        .map(|s| s.parse::<usize>().unwrap());

    let (
        transparent_hugepage_enabled,
        transparent_hugepage_defrag,
        transparent_hugepage_khugepaged_defrag,
    ) = if sub_m.is_present("DISABLE_THP") {
        ("never".into(), "never".into(), 0)
    } else if sub_m.is_present("THP_HUGE_ADDR") {
        ("never".into(), "never".into(), 0)
    } else if sub_m.is_present("THP_HUGE_ADDR_RANGES") {
        ("never".into(), "never".into(), 0)
    } else if hawkeye {
        // Default values
        ("always".into(), "madvise".into(), 1)
    } else {
        ("always".into(), "always".into(), 1)
    };

    let (
        transparent_hugepage_khugepaged_alloc_sleep_ms,
        transparent_hugepage_khugepaged_scan_sleep_ms,
    ) = if hawkeye {
        (60000, 10000)
    } else {
        (1000, 1000)
    };

    let transparent_hugepage_huge_addr = sub_m
        .value_of("THP_HUGE_ADDR")
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap());
    let transparent_hugepage_huge_addr = if sub_m.is_present("THP_HUGE_ADDR_LE") {
        Some(ThpHugeAddrMode::Less {
            addr: transparent_hugepage_huge_addr.unwrap(),
        })
    } else if sub_m.is_present("THP_HUGE_ADDR_GE") {
        Some(ThpHugeAddrMode::Greater {
            addr: transparent_hugepage_huge_addr.unwrap(),
        })
    } else if let Some(ranges) = sub_m.values_of("THP_HUGE_ADDR_RANGES") {
        let ranges = ranges.collect::<Vec<_>>();

        // Do some sanity checking.
        if ranges.len() % 2 != 0 {
            panic!("Odd number of end points for THP_HUGE_ADDR_RANGES. Missing an endpoint.");
        }

        let ranges = ranges
            .chunks_exact(2)
            .map(|c| {
                let mut c = c
                    .into_iter()
                    .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap());
                let first = c.next().unwrap();
                let second = c.next().unwrap();
                assert!(first < second, "Range {} {} is backwards.", first, second);
                (first, second)
            })
            .collect();

        Some(ThpHugeAddrMode::Ranges { ranges })
    } else if sub_m.is_present("THP_HUGE_ADDR") {
        Some(ThpHugeAddrMode::Equal {
            addr: transparent_hugepage_huge_addr.unwrap(),
        })
    } else {
        None
    };

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = crate::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::get_remote_research_settings(&ushell)?;

    let perf_counters = crate::cpu::default_perf_counters(&ushell)?;
    let perf_counters: Vec<String> = sub_m
        .values_of("PERF_COUNTER")
        .map_or(perf_counters, |counters| counters.map(Into::into).collect());

    let cfg = Config {
        exp: (10, "bare_metal".into()),

        workload,

        eager,
        fragmentation,

        transparent_hugepage_enabled,
        transparent_hugepage_defrag,
        transparent_hugepage_khugepaged_defrag,
        transparent_hugepage_khugepaged_alloc_sleep_ms,
        transparent_hugepage_khugepaged_scan_sleep_ms,
        transparent_hugepage_huge_addr,

        mmstats,
        meminfo_periodic,
        damon,
        damon_sample_interval,
        damon_aggr_interval,
        memtrace,
        mmu_overhead,
        perf_record,
        perf_counters,
        smaps_periodic,
        mmap_tracker,
        kbadgerd,
        kbadgerd_sleep_interval,
        mm_econ,
        mm_econ_benefit_file,
        enable_aslr,
        pftrace,
        bpf_pftrace,
        asynczero,
        hawkeye,
        eagerprofile,

        username: login.username.into(),
        host: login.hostname.into(),

        local_git_hash,
        remote_git_hash,

        remote_research_settings,

        timestamp: Timestamp::now(),
    };

    run_inner(&login, &cfg)
}

pub fn turn_on_huge_addr(
    shell: &SshShell,
    huge_addr: ThpHugeAddrMode,
    process: ThpHugeAddrProcess,
) -> Result<(), failure::Error> {
    let mode = match huge_addr {
        ThpHugeAddrMode::Equal { .. } => 0,
        ThpHugeAddrMode::Less { .. } => 1,
        ThpHugeAddrMode::Greater { .. } => 2,
        ThpHugeAddrMode::Ranges { .. } => 3,
    };

    shell.run(cmd!(
        "echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/huge_addr_mode",
        mode
    ))?;

    match huge_addr {
        ThpHugeAddrMode::Equal { addr }
        | ThpHugeAddrMode::Less { addr }
        | ThpHugeAddrMode::Greater { addr } => {
            shell.run(cmd!(
                "echo 0x{:x} | sudo tee /sys/kernel/mm/transparent_hugepage/huge_addr",
                addr
            ))?;
        }
        ThpHugeAddrMode::Ranges { ranges } => {
            let addrs = ranges
                .into_iter()
                .map(|(start, end)| format!("{} {}", start, end))
                .collect::<Vec<_>>()
                .join(";");
            shell.run(cmd!(
                "echo \"{}\" | sudo tee /sys/kernel/mm/transparent_hugepage/huge_addr",
                addrs
            ))?;
        }
    }

    match process {
        ThpHugeAddrProcess::Pid(pid) => {
            shell.run(cmd!(
                "echo {} | sudo tee /sys/kernel/mm/transparent_hugepage/huge_addr_pid",
                pid
            ))?;
        }
        ThpHugeAddrProcess::Command(name) => {
            shell.run(cmd!(
                "echo -n {} | sudo tee /sys/kernel/mm/transparent_hugepage/huge_addr_comm",
                name
            ))?;
        }
    }

    Ok(())
}

pub struct InitialSetupState<'s> {
    pub user_home: String,
    pub zerosim_exp_path: String,
    pub results_dir: String,
    pub output_file: String,
    pub time_file: String,
    pub sim_file: String,
    pub mmstats_file: String,
    pub damon_output_path: String,
    pub trace_file: String,
    pub ycsb_result_file: String,
    pub badger_trap_file: String,
    pub pftrace_file: String,
    pub pftrace_rejected_file: String,
    pub runtime_file: String,
    pub bmks_dir: String,
    pub damon_path: String,
    pub pin_path: String,
    pub mmap_filter_csv_files: HashMap<String, String>,
    pub mmu_overhead: Option<(String, Vec<String>)>,
    pub cores: usize,
    pub tctx: TasksetCtx,
    pub bgctx: BackgroundContext<'s>,
    pub instrumented_proc: Option<String>,
    pub kbadgerd_thread: Option<spurs::SshSpawnHandle>,
    pub sleeping_fragmenter: Option<spurs::SshSpawnHandle>,
    pub bpf_trace_thread: Option<spurs::SshSpawnHandle>,
    pub eagerprofile_thread: Option<spurs::SshSpawnHandle>,
}

pub fn initial_setup<'s, P: Parametrize>(
    ushell: &'s SshShell,
    output: &'s P,
    asynczero: bool,
    hawkeye: bool,
    enable_aslr: bool,
    transparent_hugepage_enabled: &str,
    transparent_hugepage_defrag: &str,
    transparent_hugepage_khugepaged_defrag: usize,
    transparent_hugepage_khugepaged_alloc_sleep_ms: usize,
    transparent_hugepage_khugepaged_scan_sleep_ms: usize,
    mmstats: bool,
    meminfo_periodic: bool,
    smaps_periodic: bool,
    mmap_tracker: bool,
    mm_econ: bool,
    pftrace: Option<usize>,
    bpf_pftrace: Option<usize>,
    kbadgerd: bool,
    kbadgerd_sleep_interval: Option<usize>,
    eager: bool,
    fragmentation: Option<usize>,
    eagerprofile: Option<usize>,
    // Returns false if there was an exception and this should be skipped...
    transparent_hugepage_excpetion_hack: impl FnOnce(&SshShell) -> Result<bool, failure::Error>,
    compute_mmap_filter_csv_files: impl FnOnce(&str) -> HashMap<String, String>,
    compute_mmu_overhead: impl FnOnce(
        &SshShell,
        &str,
    ) -> Result<Option<(String, Vec<String>)>, failure::Error>,
    compute_instrumented_proc: impl FnOnce() -> Option<String>,
    set_huge_addr: impl FnOnce(&SshShell, &Option<String>) -> Result<(), failure::Error>,
    save_mmap_filter_benefits: impl FnOnce(
        &SshShell,
        &HashMap<String, String>,
    ) -> Result<(), failure::Error>,
    kbadgerd_early_start_exceptions: bool,
    choose_eager_paging_process: impl FnOnce(&Option<String>) -> Vec<String>,
    hawkeye_debloat_process: impl FnOnce(&Option<String>) -> String,
) -> Result<InitialSetupState<'s>, failure::Error> {
    let user_home = get_user_home_dir(&ushell)?;
    let zerosim_exp_path = dir!(
        &user_home,
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );

    // Start asynczeroing daemon and throttle it up a bit.
    if asynczero {
        ushell.run(cmd!(
            "ls /sys/kernel/mm/asynczero || \
            sudo insmod $(ls -t1 kernel-*/kbuild/vmlinux | head -n1 | cut -d / -f1)/kbuild/mm/asynczero/asynczero.ko"
        ))?;
        // We have a small bootstrapping problem... we start off without any prezeroed pages, so we
        // never get to see what their benefit is, so we never prezero any pages, so ...
        //
        // Instead, we temporarily disable mm_econ at the beginning, while we warm up.
        ushell.run(cmd!(
            "echo 1 | sudo tee /sys/module/asynczero/parameters/mode"
        ))?;
    }
    if hawkeye {
        ushell.run(cmd!(
            "sudo insmod HawkEye/kbuild/hawkeye_modules/async-zero/asynczero.ko"
        ))?;
    }

    // Turn of ASLR
    if enable_aslr {
        // ASLR is enabled by default on startup, so this probably isn't
        // necessary, but it's good to be explicit.
        crate::enable_aslr(&ushell)?;
    } else {
        crate::disable_aslr(&ushell)?;
    }

    // Allow `perf` as any user
    crate::perf_for_all(&ushell)?;

    // Turn on/off compaction and force it to happen if needed
    if transparent_hugepage_excpetion_hack(&ushell)? {
        crate::turn_on_thp(
            &ushell,
            transparent_hugepage_enabled,
            transparent_hugepage_defrag,
            transparent_hugepage_khugepaged_defrag,
            transparent_hugepage_khugepaged_alloc_sleep_ms,
            transparent_hugepage_khugepaged_scan_sleep_ms,
        )?;
    }

    // Turn of NUMA balancing
    crate::set_auto_numa(&ushell, false /* off */)?;

    // Generate a bunch of output paths.
    let results_dir = dir!(&user_home, setup00000::HOSTNAME_SHARED_RESULTS_DIR);

    let (output_file, params_file, time_file, sim_file) = output.gen_standard_names();
    let output_file = dir!(&results_dir, output_file);
    let mmstats_file = dir!(&results_dir, output.gen_file_name("mmstats"));
    let meminfo_file = dir!(&results_dir, output.gen_file_name("meminfo"));
    let smaps_file = dir!(&results_dir, output.gen_file_name("smaps"));
    let mmap_tracker_file = dir!(&results_dir, output.gen_file_name("mmap"));
    let damon_output_path = dir!(&results_dir, output.gen_file_name("damon"));
    let trace_file = dir!(&results_dir, output.gen_file_name("trace"));
    let mmu_overhead_file = dir!(&results_dir, output.gen_file_name("mmu"));
    let ycsb_result_file = dir!(&results_dir, output.gen_file_name("ycsb"));
    let badger_trap_file = dir!(&results_dir, output.gen_file_name("bt"));
    let pftrace_file = dir!(&results_dir, output.gen_file_name("pftrace"));
    let pftrace_rejected_file = dir!(&results_dir, output.gen_file_name("rejected"));
    let runtime_file = dir!(&results_dir, output.gen_file_name("runtime"));
    let frag_file = dir!(&results_dir, output.gen_file_name("precondition.frag"));
    let eagerprofile_file = dir!(&results_dir, output.gen_file_name("eagerprofile"));

    let bmks_dir = dir!(&user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_BENCHMARKS_DIR);
    let damon_path = dir!(&bmks_dir, DAMON_PATH);
    let pin_path = dir!(
        &user_home,
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_MEMBUFFER_EXTRACT_SUBMODULE,
        "pin"
    );
    let swapnil_path = dir!(&bmks_dir, ZEROSIM_SWAPNIL_PATH);

    ushell.run(cmd!(
        "echo {} > {}",
        escape_for_bash(&serde_json::to_string(&output)?),
        dir!(&results_dir, params_file)
    ))?;

    let mmap_filter_csv_files = compute_mmap_filter_csv_files(&results_dir);
    let mmu_overhead = compute_mmu_overhead(&ushell, &mmu_overhead_file)?;

    let cores = crate::get_num_cores(&ushell)?;
    let tctx = TasksetCtx::new(cores);

    if mmstats {
        // Print the current numbers, 'cause why not?
        ushell.run(cmd!("tail /proc/mm_*"))?;

        // Writing to any of the params will reset the plot.
        ushell.run(cmd!(
            "for h in /proc/mm_*_min ; do echo $h ; echo 0 | sudo tee $h ; done"
        ))?;
    }

    // Maybe collect meminfo
    let mut bgctx = BackgroundContext::new(&ushell);
    if meminfo_periodic {
        bgctx.spawn(BackgroundTask {
            name: "meminfo",
            period: PERIOD,
            cmd: format!("cat /proc/meminfo | tee -a {}", &meminfo_file),
            ensure_started: meminfo_file,
        })?;
    }

    let instrumented_proc = compute_instrumented_proc();

    if smaps_periodic {
        bgctx.spawn(BackgroundTask {
            name: "smaps",
            period: PERIOD,
            cmd: format!(
                "((sudo cat /proc/`pgrep -x {}  | sort -n \
                    | head -n1`/smaps) || echo none) | tee -a {}",
                instrumented_proc.as_ref().unwrap(),
                &smaps_file
            ),
            ensure_started: smaps_file,
        })?;
    }

    if mmap_tracker {
        // This is needed for BPF to compile, but we don't want it enabled all
        // of the time because it interferes with gcc and g++
        let enable_bpf_cmd = "source scl_source enable devtoolset-7 llvm-toolset-7";

        ushell.spawn(cmd!(
            "{}; \
            sudo {}/bmks/mmap_tracker.py -c {} | tee {}",
            enable_bpf_cmd,
            &dir!(&user_home, RESEARCH_WORKSPACE_PATH),
            instrumented_proc.as_ref().unwrap(),
            mmap_tracker_file
        ))?;
        // Wait some time for the BPF validator to do its job
        println!("Waiting 10s for BPF validator...");
        ushell.run(cmd!("sleep 10"))?;
    }

    // Set `huge_addr` if needed.
    set_huge_addr(ushell, &instrumented_proc)?;

    // Turn on mm_econ if needed.
    if mm_econ {
        // Set frequency.
        let freq_ghz = ushell
            .run(cmd!(
                "lscpu | grep 'Model' | grep -o '[0-9\\.]\\+GHz' | grep -o '[0-9\\.]\\+'"
            ))?
            .stdout
            .trim()
            .parse::<f64>()
            .unwrap();
        let freq_mhz = (freq_ghz * 1000.) as u64;
        ushell.run(cmd!(
            "echo {} | sudo tee /sys/kernel/mm/mm_econ/freq_mhz",
            freq_mhz
        ))?;

        ushell.run(cmd!("echo 1 | sudo tee /sys/kernel/mm/mm_econ/enabled"))?;
    }

    // Save mmap filters with other workload output.
    save_mmap_filter_benefits(ushell, &mmap_filter_csv_files)?;

    if mm_econ {
        ushell.run(cmd!("cat /sys/kernel/mm/mm_econ/stats"))?;
    }

    if let Some(threshold) = pftrace {
        ushell.run(cmd!("echo 1 | sudo tee /proc/pftrace_enable"))?;
        ushell.run(cmd!(
            "echo {} | sudo tee /proc/pftrace_threshold",
            threshold
        ))?;
    }

    let bpf_trace_thread = if let Some(threshold) = bpf_pftrace {
        ushell.run(cmd!("rm -f /tmp/stop-pf-bpf"))?;
        let handle = ushell.spawn(cmd!(
            "(source scl_source enable devtoolset-7 llvm-toolset-7 ; \
             sudo  {}/page_fault_bpf.py -t {} ) > {}",
            &bmks_dir,
            threshold,
            &pftrace_file,
        ))?;

        // Wait to begin...
        ushell.run(cmd!("while ! [ -e {} ] ; do sleep 1 ; done", &pftrace_file))?;

        Some(handle)
    } else {
        None
    };

    // Turn on kbadgerd if needed.
    if kbadgerd {
        ushell.run(cmd!(
            "ls /sys/kernel/mm/kbadgerd || \
            sudo insmod $(ls -t1 kernel-*/kbuild/vmlinux \
                | head -n1 | cut -d / -f1)/kbuild/mm/kbadgerd/kbadgerd.ko"
        ))?;
    }
    if let Some(sleep_interval) = kbadgerd_sleep_interval {
        ushell.run(cmd!(
            "echo {} | sudo tee /sys/kernel/mm/kbadgerd/sleep_interval",
            sleep_interval
        ))?;
    }

    let kbadgerd_thread = if kbadgerd && !kbadgerd_early_start_exceptions {
        Some(ushell.spawn(cmd!(
            "while ! [ `pgrep -x {pname}` ] ; do echo 'Waiting for process {pname}' ; done ; \
             echo `pgrep -x {pname}` | sudo tee /sys/kernel/mm/kbadgerd/enabled",
            pname = instrumented_proc.as_ref().unwrap()
        ))?)
    } else {
        None
    };

    if asynczero || hawkeye {
        // Wait a bit for zeroing daemons to warm up a bit.
        println!("sleeping a bit to give asynczero warmup time...");
        std::thread::sleep(std::time::Duration::from_secs(10));

        ushell.run(cmd!(
            "sudo cat /sys/module/asynczero/parameters/pages_zeroed"
        ))?;
    }
    if asynczero {
        ushell.run(cmd!(
            "echo 0 | sudo tee /sys/module/asynczero/parameters/mode"
        ))?;
        // NOTE: here the count is in individual 4KB pages.
        ushell.run(cmd!(
            "echo 10 | sudo tee /sys/module/asynczero/parameters/count"
        ))?;
        ushell.run(cmd!(
            "echo 100 | sudo tee /sys/module/asynczero/parameters/sleep"
        ))?;
    }
    if hawkeye {
        // Just use the default parameters of the module...
        //
        // NOTE: here the count is in terms of compond pages, which could be of any
        // power-of-two size.
        //ushell.run(cmd!(
        //    "echo 10 | sudo tee /sys/module/asynczero/parameters/count"
        //))?;
    }

    // Turn on hawkeye bloat removal thread and profiler if needed.
    if hawkeye {
        let debloat_process = hawkeye_debloat_process(&instrumented_proc);
        ushell.run(cmd!(
            "sudo insmod HawkEye/kbuild/hawkeye_modules/bloat_recovery/remove.ko \
                 debloat_comm={}",
            debloat_process
        ))?;
        // 120s sleep between debloating, according to Ashish Panwar.
        ushell.run(cmd!(
            "echo 120 | sudo tee /sys/module/remove/parameters/sleep"
        ))?;

        // Use default interval of 10s -- Ashish Panwar.
        ushell.run(cmd!(
            "./x86-MMU-Profiler/global_profile -d -p {} {}",
            debloat_process,
            match cpu_family_model(ushell)? {
                Processor::Intel(IntelX86Model::SkyLakeServer) => "-f skylakesp",
                Processor::Intel(IntelX86Model::HaswellConsumer) => "-f haswell",

                _ => unimplemented!(),
            }
        ))?;

        // promotion_metric: default 0 = HawkEye-PMU; 2 = HawkEye-G.
        // scan_sleep_millisecs: 1000 for Fig 8 (HawkEye paper) experiments.
    }

    // Turn on eager paging if needed.
    if eager {
        setup_apriori_paging_processes(
            ushell,
            &swapnil_path,
            &choose_eager_paging_process(&instrumented_proc),
        )?;
    }

    // Fragment memory if needed.
    let sleeping_fragmenter = if let Some(percentage) = fragmentation {
        ushell.run(cmd!(
            "echo 1 | sudo tee /sys/module/page_alloc/parameters/shuffle_trigger"
        ))?;
        ushell.run(cmd!("dmesg | grep page_alloc"))?;
        ushell.run(cmd!("sudo rm -f /tmp/fragmented_sentinel"))?;
        let handle = ushell.spawn(cmd!("sudo ./fragment_memory {}", percentage).cwd(&bmks_dir))?;
        ushell.run(cmd!(
            "while [ ! -e /tmp/fragmented_sentinel ] ; do sleep 1 ; done ;"
        ))?;
        ushell.run(cmd!("./buddyinfo | tee {}", frag_file).cwd(&bmks_dir))?;

        Some(handle)
    } else {
        None
    };

    // Record pagemap info if needed.
    let eagerprofile_thread = if let Some(interval) = eagerprofile {
        let thread = ushell.spawn(
            cmd!(
                "while ! [ `pgrep -x {pname}` ] ; do echo 'Waiting for {pname}'; sleep 10 ; done ; \
                sudo ./target/release/eagerprofiling `pgrep -x {pname}` {} | tee {}",
                interval,
                &eagerprofile_file,
                pname = instrumented_proc.as_ref().unwrap(),
            )
            .cwd(dir!(&bmks_dir, "eagerprofiling")),
        )?;

        Some(thread)
    } else {
        None
    };

    Ok(InitialSetupState {
        user_home,
        zerosim_exp_path,
        results_dir,
        output_file,
        time_file,
        sim_file,
        mmstats_file,
        damon_output_path,
        trace_file,
        ycsb_result_file,
        badger_trap_file,
        pftrace_file,
        pftrace_rejected_file,
        mmap_filter_csv_files,
        runtime_file,
        bmks_dir,
        damon_path,
        pin_path,
        mmu_overhead,
        cores,
        tctx,
        bgctx,
        instrumented_proc,
        kbadgerd_thread,
        sleeping_fragmenter,
        bpf_trace_thread,
        eagerprofile_thread,
    })
}

pub fn teardown(
    ushell: &SshShell,
    timers: &mut Vec<(&str, Duration)>,
    bgctx: BackgroundContext,
    pftrace: Option<usize>,
    mm_econ: bool,
    mmstats: bool,
    meminfo_periodic: bool,
    smaps_periodic: bool,
    damon: bool,
    kbadgerd: bool,
    results_dir: &str,
    pftrace_rejected_file: &str,
    pftrace_file: &str,
    bpf_trace_thread: Option<spurs::SshSpawnHandle>,
    mmstats_file: &str,
    badger_trap_file: &str,
    time_file: &str,
    sim_file: &str,
    damon_off_exception: bool,
    eagerprofile_thread: Option<spurs::SshSpawnHandle>,
) -> Result<(), failure::Error> {
    if pftrace.is_some() {
        ushell.run(cmd!("echo 0 | sudo tee /proc/pftrace_enable"))?;
        ushell.run(cmd!(
            "cat /proc/pftrace_rejected | tee {}",
            pftrace_rejected_file
        ))?;
        ushell.run(cmd!("cat /proc/pftrace_discarded_from_interrupt"))?;
        ushell.run(cmd!("cat /proc/pftrace_discarded_from_error"))?;
        ushell.run(cmd!("sync"))?;
        ushell.run(cmd!("cp /pftrace {}", pftrace_file))?;
    }
    if let Some(handle) = bpf_trace_thread {
        ushell.run(cmd!("touch /tmp/stop-pf-bpf"))?;
        handle.join().1?;
    }

    if mm_econ {
        ushell.run(cmd!("cat /sys/kernel/mm/mm_econ/stats"))?;
    }

    if mmstats {
        ushell.run(cmd!("tail /proc/mm_* | tee {}", mmstats_file))?;
        ushell.run(cmd!("cat /proc/meminfo | tee -a {}", mmstats_file))?;
        ushell.run(cmd!("cat /proc/vmstat | tee -a {}", mmstats_file))?;

        if mm_econ {
            ushell.run(cmd!(
                "cat /sys/kernel/mm/mm_econ/stats | tee -a {}",
                mmstats_file
            ))?;
        }
    }

    if meminfo_periodic || smaps_periodic {
        time!(
            timers,
            "Waiting for data collectioned threads to halt",
            bgctx.notify_and_join_all()?
        );
    }

    if let Some(thread) = eagerprofile_thread {
        thread.join().1?;
    }

    // Tell damon to write data, if needed. (Graph500 waits for damon to finish, so we don't need
    // to do it again).
    if damon && !damon_off_exception {
        time!(timers, "Waiting for DAMON to flush data buffers", {
            ushell.run(cmd!(
                "echo off | sudo tee /sys/kernel/debug/damon/monitor_on"
            ))?;
        })
    }

    // Extract relevant data from dmesg for kbadgerd, if needed.
    if kbadgerd {
        ushell.run(cmd!("echo off | sudo tee /sys/kernel/mm/kbadgerd/enabled"))?;
        // We wait until the results have been written...
        while ushell
            .run(cmd!("dmesg | grep -q 'kbadgerd: END Results'"))
            .is_err()
        {
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
        ushell.run(cmd!("dmesg | grep 'kbadgerd:' | tee {}", badger_trap_file))?;
    }

    ushell.run(cmd!("date"))?;

    ushell.run(cmd!("free -h"))?;

    ushell.run(cmd!(
        "echo {} > {}",
        escape_for_bash(&crate::timings_str(timers.as_slice())),
        dir!(results_dir, time_file)
    ))?;

    crate::gen_standard_host_output(sim_file, ushell)?;

    Ok(())
}

fn run_inner<A>(login: &Login<A>, cfg: &Config) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Reboot
    initial_reboot(&login)?;

    // Connect
    let ushell = connect_and_setup_host_only(&login)?;

    let InitialSetupState {
        ref user_home,
        ref zerosim_exp_path,
        ref results_dir,
        ref output_file,
        ref time_file,
        ref sim_file,
        ref mmstats_file,
        ref damon_output_path,
        ref trace_file,
        ref ycsb_result_file,
        ref badger_trap_file,
        ref pftrace_file,
        ref pftrace_rejected_file,
        ref mmap_filter_csv_files,
        ref runtime_file,
        ref bmks_dir,
        ref damon_path,
        ref pin_path,
        mmu_overhead,

        instrumented_proc: _,

        mut tctx,
        bgctx,
        kbadgerd_thread: _kbadgerd_thread,
        sleeping_fragmenter: _sleeping_fragmenter,
        bpf_trace_thread,
        eagerprofile_thread,

        cores: _,
    } = initial_setup(
        &ushell,
        cfg,
        cfg.asynczero,
        cfg.hawkeye,
        cfg.enable_aslr,
        &cfg.transparent_hugepage_enabled,
        &cfg.transparent_hugepage_defrag,
        cfg.transparent_hugepage_khugepaged_defrag,
        cfg.transparent_hugepage_khugepaged_alloc_sleep_ms,
        cfg.transparent_hugepage_khugepaged_scan_sleep_ms,
        cfg.mmstats,
        cfg.meminfo_periodic,
        cfg.smaps_periodic,
        cfg.mmap_tracker,
        cfg.mm_econ,
        cfg.pftrace,
        cfg.bpf_pftrace,
        cfg.kbadgerd,
        cfg.kbadgerd_sleep_interval,
        cfg.eager,
        cfg.fragmentation,
        cfg.eagerprofile,
        // THP exception hack
        |shell| {
            if matches!(cfg.workload, Workload::ThpUbmkShm { .. }) {
                crate::turn_on_thp(
                    shell,
                    /* enabled */ "never",
                    /* defrag */ "never",
                    cfg.transparent_hugepage_khugepaged_defrag,
                    cfg.transparent_hugepage_khugepaged_alloc_sleep_ms,
                    cfg.transparent_hugepage_khugepaged_scan_sleep_ms,
                )?;

                // Reserve a huge page and use it for a hugetlbfs.
                shell.run(cmd!("sudo sysctl vm.nr_hugepages=4"))?;
                shell.run(cmd!("sudo mkdir -p /mnt/huge"))?;
                shell.run(cmd!(
                    "sudo mount -t hugetlbfs -o \
                     uid=`id -u`,gid=`id -g`,pagesize=2M,size=8M \
                     none /mnt/huge"
                ))?;

                Ok(false)
            } else {
                // Run normal thp init...
                Ok(true)
            }
        },
        // Compute mmap_filters_csv_files
        |results_dir| {
            // This closure returns a map of "process name" -> "mmap filter csv fname",
            // but we only have single-process workloads here, so the name doesn't matter.
            let fname = dir!(results_dir, cfg.gen_file_name("mmap-filters.csv"));
            vec![("fakeprocessname".into(), fname)]
                .into_iter()
                .collect()
        },
        // Compute mmu_overhead
        |_shell, mmu_overhead_file| {
            Ok(if cfg.mmu_overhead {
                Some((mmu_overhead_file.to_owned(), cfg.perf_counters.clone()))
            } else {
                None
            })
        },
        // Compute instrumented proc name
        || {
            let nas_proc_name = if let Workload::NasCG { class } = cfg.workload {
                Some(format!("cg.{}.x", class))
            } else {
                None
            };
            Some(
                match cfg.workload {
                    Workload::TimeLoop { .. } => "time_loop",
                    Workload::LocalityMemAccess { .. } => "locality_mem_access",
                    Workload::TimeMmapTouch { .. } => "time_mmap_touch",
                    Workload::ThpUbmk { .. } => "ubmk",
                    Workload::ThpUbmkShm { .. } => "ubmk-shm",
                    Workload::Redis { .. } | Workload::RedisYcsb { .. } => "redis-server",
                    Workload::Memcached { .. } | Workload::MemcachedYcsb { .. } => "memcached",
                    Workload::MongoDB { .. } => "mongod",
                    Workload::Graph500 { .. } => "graph500",
                    Workload::Spec2017Xz { .. } => "xz_s",
                    Workload::Spec2017Mcf { .. } => "mcf_s",
                    Workload::Spec2017Xalancbmk { .. } => "xalancbmk_s",
                    Workload::Canneal { .. } => "canneal",
                    Workload::NasCG { .. } => nas_proc_name.as_ref().map(String::as_str).unwrap(),
                }
                .to_owned(),
            )
        },
        // Set THP huge_addr
        |shell, proc_name| {
            if let Some(ref huge_addr) = cfg.transparent_hugepage_huge_addr {
                turn_on_huge_addr(
                    shell,
                    huge_addr.clone(),
                    ThpHugeAddrProcess::from_name(proc_name.as_ref().unwrap()),
                )?;
            }

            Ok(())
        },
        // Save all benefit files with the other output for the workload.
        |shell, mmap_filter_csv_files| {
            // If a benefits file was passed, save it with the other output and generate a cb_wrapper
            // command for running the workload.
            if let Some(filename) = &cfg.mm_econ_benefit_file {
                // Do some sanity checking first...
                match cfg.workload {
                    Workload::TimeLoop { .. }
                    | Workload::LocalityMemAccess { .. }
                    | Workload::TimeMmapTouch { .. }
                    | Workload::Graph500 { .. } => unimplemented!(),

                    Workload::ThpUbmk { .. }
                    | Workload::ThpUbmkShm { .. }
                    | Workload::Memcached { .. }
                    | Workload::MemcachedYcsb { .. }
                    | Workload::Redis { .. }
                    | Workload::RedisYcsb { .. }
                    | Workload::MongoDB { .. }
                    | Workload::Spec2017Mcf
                    | Workload::Spec2017Xalancbmk { .. }
                    | Workload::Spec2017Xz { .. }
                    | Workload::Canneal { .. }
                    | Workload::NasCG { .. } => {}
                }

                println!("Reading mm_econ benefit file: {}", filename);
                let filter_csv = fs::read_to_string(filename)?;
                let mmap_filter_csv_file = mmap_filter_csv_files.iter().next().unwrap().1;

                // Be sure to save the contents of the mmap_filter in the results so we can
                // reference them later.  We do it this round-about way because otherwise the
                // command may become too long for SSH...
                for line in filter_csv.lines() {
                    shell.run(cmd!(
                        "echo {} >> {}",
                        escape_for_bash(&line),
                        &mmap_filter_csv_file
                    ))?;
                }

                shell.run(cmd!("cat {}", mmap_filter_csv_file))?;
            }

            Ok(())
        },
        // Exceptions for early-starting kbadgerd.
        matches!(
            cfg.workload,
            Workload::Memcached { .. } | Workload::MongoDB { .. }
        ),
        // Choose eager paging process.
        |proc_name| vec![proc_name.clone().unwrap()],
        // Choose hawkeye debloating process.
        |proc_name| proc_name.clone().unwrap(),
    )?;

    let mmu_overhead = if let Some((ref file, ref counters)) = mmu_overhead {
        Some((file.as_str(), counters.as_slice()))
    } else {
        None
    };

    let cb_wrapper_cmd = cfg.mm_econ_benefit_file.as_ref().map(|_| {
        gen_cb_wrapper_command_prefix(
            dir!(bmks_dir, "cb_wrapper"),
            mmap_filter_csv_files.into_iter().next().unwrap().1,
        )
    });
    let cb_wrapper_cmd = cb_wrapper_cmd.as_ref().map(String::as_str);

    // Collect timers on VM
    let mut timers = vec![];

    // Run the workload.
    match cfg.workload {
        Workload::TimeLoop { n } => {
            time!(
                timers,
                "Workload",
                run_time_loop(&ushell, zerosim_exp_path, n, output_file, &mut tctx,)?
            );
        }

        Workload::LocalityMemAccess { n } => {
            let local_file = cfg.gen_file_name("local");
            let nonlocal_file = cfg.gen_file_name("nonlocal");

            time!(timers, "Workload", {
                run_locality_mem_access(
                    &ushell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Local,
                        n: n,
                        threads: None,
                        output_file: &dir!(results_dir, local_file),
                    },
                )?;
                run_locality_mem_access(
                    &ushell,
                    &LocalityMemAccessConfig {
                        exp_dir: zerosim_exp_path,
                        locality: LocalityMemAccessMode::Random,
                        n: n,
                        threads: None,
                        output_file: &dir!(results_dir, nonlocal_file),
                    },
                )?;
            });
        }

        Workload::TimeMmapTouch { size, pattern } => {
            time!(
                timers,
                "Workload",
                run_time_mmap_touch(
                    &ushell,
                    &TimeMmapTouchConfig {
                        exp_dir: zerosim_exp_path,
                        pages: (size << 30) >> 12,
                        pattern: pattern,
                        prefault: false,
                        pf_time: None,
                        output_file: Some(output_file),
                        pin_core: tctx.next(),
                    }
                )?
            );
        }

        Workload::ThpUbmk { size, reps } => {
            time!(
                timers,
                "Workload",
                run_thp_ubmk(
                    &ushell,
                    size,
                    reps,
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, THP_UBMK_DIR),
                    cb_wrapper_cmd,
                    mmu_overhead,
                    if cfg.perf_record {
                        Some(&trace_file)
                    } else {
                        None
                    },
                    &runtime_file,
                    tctx.next(),
                )?
            );
        }

        Workload::ThpUbmkShm { size, reps } => {
            time!(
                timers,
                "Workload",
                run_thp_ubmk_shm(
                    &ushell,
                    size,
                    reps,
                    cfg.transparent_hugepage_enabled == "always",
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, THP_UBMK_DIR),
                    cb_wrapper_cmd,
                    mmu_overhead,
                    if cfg.perf_record {
                        Some(&trace_file)
                    } else {
                        None
                    },
                    tctx.next(),
                )?
            );
        }

        Workload::Memcached { size } => {
            let freq = get_cpu_freq(&ushell)?;

            time!(
                timers,
                "Workload",
                run_memcached_gen_data(
                    &ushell,
                    &MemcachedWorkloadConfig {
                        user: login.username,
                        exp_dir: zerosim_exp_path,
                        memcached: &dir!(
                            user_home.as_str(),
                            RESEARCH_WORKSPACE_PATH,
                            ZEROSIM_MEMCACHED_SUBMODULE
                        ),
                        server_size_mb: size << 10,
                        wk_size_gb: size,
                        freq: Some(freq),
                        allow_oom: true,
                        pf_time: None,
                        output_file: Some(output_file),
                        server_pin_core: Some(tctx.next()),
                        client_pin_core: {
                            tctx.skip();
                            tctx.next()
                        },
                        pintool: if cfg.memtrace {
                            Some(Pintool::MemTrace {
                                pin_path: &pin_path,
                                output_path: &trace_file,
                            })
                        } else {
                            None
                        },
                        damon: if cfg.damon {
                            Some(Damon {
                                damon_path: &damon_path,
                                output_path: &damon_output_path,
                                sample_interval: cfg.damon_sample_interval,
                                aggregate_interval: cfg.damon_aggr_interval,
                            })
                        } else {
                            None
                        },
                        cb_wrapper_cmd,
                        mmu_perf: mmu_overhead,
                        server_start_cb: |shell| {
                            // Set `huge_addr` if needed.
                            if let Some(ref huge_addr) = cfg.transparent_hugepage_huge_addr {
                                let memcached_pid = shell
                                    .run(cmd!("pgrep memcached"))?
                                    .stdout
                                    .as_str()
                                    .trim()
                                    .parse::<usize>()?;
                                turn_on_huge_addr(
                                    shell,
                                    huge_addr.clone(),
                                    ThpHugeAddrProcess::Pid(memcached_pid),
                                )?;
                            }
                            // Turn on kbadgerd if needed.
                            if cfg.kbadgerd {
                                let memcached_pid = shell
                                    .run(cmd!("pgrep memcached"))?
                                    .stdout
                                    .as_str()
                                    .trim()
                                    .parse::<usize>()?;
                                ushell.run(cmd!(
                                    "echo {} | sudo tee /sys/kernel/mm/kbadgerd/enabled",
                                    memcached_pid
                                ))?;
                            }
                            Ok(())
                        },
                    },
                    &runtime_file
                )?
            );
        }

        Workload::MemcachedYcsb {
            size,
            op_count,
            read_prop,
            update_prop,
        } => {
            let freq = get_cpu_freq(&ushell)?;
            let ycsb_path = &dir!(bmks_dir, "YCSB");
            let memcached_cfg = MemcachedWorkloadConfig {
                user: login.username,
                exp_dir: zerosim_exp_path,
                memcached: &dir!(
                    user_home.as_str(),
                    RESEARCH_WORKSPACE_PATH,
                    ZEROSIM_MEMCACHED_SUBMODULE
                ),
                server_size_mb: size << 10,
                wk_size_gb: size,
                freq: Some(freq),
                allow_oom: true,
                pf_time: None,
                output_file: Some(output_file),
                server_pin_core: Some(tctx.next()),
                client_pin_core: {
                    tctx.skip();
                    tctx.next()
                },
                pintool: if cfg.memtrace {
                    Some(Pintool::MemTrace {
                        pin_path: &pin_path,
                        output_path: &trace_file,
                    })
                } else {
                    None
                },
                damon: None,
                cb_wrapper_cmd,
                mmu_perf: None,
                server_start_cb: |shell| {
                    // Set `huge_addr` if needed.
                    if let Some(ref huge_addr) = cfg.transparent_hugepage_huge_addr {
                        let memcached_pid = shell
                            .run(cmd!("pgrep memcached"))?
                            .stdout
                            .as_str()
                            .trim()
                            .parse::<usize>()?;
                        turn_on_huge_addr(
                            shell,
                            huge_addr.clone(),
                            ThpHugeAddrProcess::Pid(memcached_pid),
                        )?;
                    }
                    Ok(())
                },
            };
            let ycsb_cfg = YcsbConfig {
                workload: YcsbWorkload::Custom {
                    record_count: op_count,
                    op_count,
                    read_prop,
                    update_prop,
                    insert_prop: 1.0 - read_prop - update_prop,
                },
                system: YcsbSystem::Memcached(memcached_cfg),
                ycsb_path,
                ycsb_result_file: Some(ycsb_result_file),
            };
            let mut ycsb = YcsbSession::new(ycsb_cfg);

            // Prepare.
            ycsb.start_and_load(&ushell)?;

            // Turn on damon if needed.
            if cfg.damon {
                let damon = Damon {
                    damon_path: &damon_path,
                    output_path: &damon_output_path,
                    sample_interval: cfg.damon_sample_interval,
                    aggregate_interval: cfg.damon_aggr_interval,
                };
                ushell.run(cmd!(
                    "sudo {}/damo record -s {} -a {} -o {} `pidof memcached`",
                    damon.damon_path,
                    damon.sample_interval,
                    damon.aggregate_interval,
                    damon.output_path,
                ))?;
            }

            // Turn on kbadgerd if needed.
            if cfg.kbadgerd {
                ushell.run(cmd!(
                    "echo `pgrep memcached` | sudo tee /sys/kernel/mm/kbadgerd/enabled",
                ))?;
            }

            // Turn on perf if needed.
            let perf_handle = if let Some((output_path, counters)) = mmu_overhead {
                let handle = ushell.spawn(cmd!(
                    "{}",
                    gen_perf_command_prefix(output_path, counters, "-p `pgrep memcached`")
                ))?;

                // Wait for perf to start collection.
                ushell
                    .run(cmd!("while [ ! -e {} ] ; do sleep 1 ; done", output_path).use_bash())?;

                Some(handle)
            } else {
                None
            };

            // Run workload.
            time!(timers, "Workload", ycsb.run(&ushell)?);

            // Make sure the server dies.
            ushell.run(cmd!("pkill -9 memcached"))?;

            // Make sure perf is done.
            if let Some(handle) = perf_handle {
                let (_, result) = handle.join();
                result?;
            }
        }

        Workload::Redis { size, nullfs } => {
            let freq = get_cpu_freq(&ushell)?;
            let nullfs_path = dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_NULLFS_SUBMODULE);
            let redis_conf_path = dir!(user_home, RESEARCH_WORKSPACE_PATH, REDIS_CONF);
            let cb_wrapper_cmd = cb_wrapper_cmd.map(|s| s.to_owned());
            let redis_config = RedisWorkloadConfig {
                exp_dir: zerosim_exp_path,
                nullfs: if nullfs {
                    Some(nullfs_path.as_str())
                } else {
                    None
                },
                redis_conf: &redis_conf_path,
                server_size_mb: size << 10,
                wk_size_gb: size,
                output_file: None,
                server_pin_core: None,
                client_pin_core: tctx.next(),
                freq: Some(freq),
                pf_time: None,
                cb_wrapper_cmd,
                pintool: None,
            };

            let _redis_handle = start_redis(&ushell, &redis_config);

            // Start perf if needed
            let perf_handle = if let Some((mmu_overhead_file, counters)) = mmu_overhead {
                let handle = ushell.spawn(cmd!(
                    "{}",
                    gen_perf_command_prefix(mmu_overhead_file, counters, "-p `pgrep redis-server`")
                ))?;

                // Wait for perf to start collection.
                ushell.run(
                    cmd!("while [ ! -e {} ] ; do sleep 1 ; done", mmu_overhead_file).use_bash(),
                )?;

                Some(handle)
            } else {
                None
            };

            // Actually run the workload
            run_redis_gen_data(&ushell, &redis_config)?.join().1?;

            // Make sure redis dies
            ushell.run(cmd!("sudo pkill -9 redis-server"))?;

            // Make sure perf is done.
            if let Some(handle) = perf_handle {
                let (_, result) = handle.join();
                result?;
            }
        }

        Workload::RedisYcsb {
            size,
            nullfs,
            op_count,
            read_prop,
            update_prop,
        } => {
            let freq = get_cpu_freq(&ushell)?;
            let ycsb_path = &dir!(bmks_dir, "YCSB");
            let nullfs_path = dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_NULLFS_SUBMODULE);
            let redis_conf_path = dir!(user_home, RESEARCH_WORKSPACE_PATH, REDIS_CONF);
            let cb_wrapper_cmd = cb_wrapper_cmd.map(|s| s.to_owned());
            let redis_config = RedisWorkloadConfig {
                exp_dir: zerosim_exp_path,
                nullfs: if nullfs {
                    Some(nullfs_path.as_str())
                } else {
                    None
                },
                redis_conf: &redis_conf_path,
                server_size_mb: size << 10,
                wk_size_gb: size,
                output_file: None,
                server_pin_core: None,
                client_pin_core: tctx.next(),
                freq: Some(freq),
                pf_time: None,
                cb_wrapper_cmd,
                pintool: None,
            };
            let ycsb_cfg: YcsbConfig<for<'a> fn(&'a _) -> _> = YcsbConfig {
                workload: YcsbWorkload::Custom {
                    record_count: op_count,
                    op_count,
                    read_prop,
                    update_prop,
                    insert_prop: 1.0 - read_prop - update_prop,
                },
                system: YcsbSystem::Redis(redis_config),
                ycsb_path,
                ycsb_result_file: Some(ycsb_result_file),
            };
            let mut ycsb = YcsbSession::new(ycsb_cfg);

            // Prepare.
            ycsb.start_and_load(&ushell)?;

            // Turn on kbadgerd if needed.
            if cfg.kbadgerd {
                if let Ok(mongod_pid) = ushell
                    .run(cmd!("pgrep mongod"))?
                    .stdout
                    .as_str()
                    .trim()
                    .parse::<usize>()
                {
                    ushell.run(cmd!(
                        "echo {} | sudo tee /sys/kernel/mm/kbadgerd/enabled",
                        mongod_pid
                    ))?;
                } else {
                    ushell.run(cmd!("echo \"Could not find process mongod.\""))?;
                }
            }

            // Start perf if needed
            let perf_handle = if let Some((mmu_overhead_file, counters)) = mmu_overhead {
                let handle = ushell.spawn(cmd!(
                    "{}",
                    gen_perf_command_prefix(mmu_overhead_file, counters, "-p `pgrep redis-server`")
                ))?;

                // Wait for perf to start collection.
                ushell.run(
                    cmd!("while [ ! -e {} ] ; do sleep 1 ; done", mmu_overhead_file).use_bash(),
                )?;

                Some(handle)
            } else {
                None
            };

            // Actually run the workload
            time!(timers, "Workload", ycsb.run(&ushell)?);

            // Make sure redis dies
            ushell.run(cmd!("sudo pkill -9 redis-server"))?;

            // Make sure perf is done.
            if let Some(handle) = perf_handle {
                let (_, result) = handle.join();
                result?;
            }
        }

        Workload::MongoDB {
            op_count,
            read_prop,
            update_prop,
            tmpfs_size,
            cache_size,
        } => {
            let ycsb_path = &dir!(bmks_dir, "YCSB");
            let mongodb_config = MongoDBWorkloadConfig {
                bmks_dir,
                db_dir: &dir!(user_home, "mongodb"),
                tmpfs_size,
                cache_size_mb: cache_size,
                server_pin_core: Some(tctx.next()),
                client_pin_core: {
                    tctx.skip();
                    tctx.next()
                },
                cb_wrapper_cmd,
                mmu_perf: mmu_overhead,
                server_start_cb: |shell| {
                    // Set `huge_addr` if needed.
                    if let Some(ref huge_addr) = cfg.transparent_hugepage_huge_addr {
                        let mongod_pid = shell
                            .run(cmd!("pgrep mongod"))?
                            .stdout
                            .as_str()
                            .trim()
                            .parse::<usize>()?;
                        turn_on_huge_addr(
                            shell,
                            huge_addr.clone(),
                            ThpHugeAddrProcess::Pid(mongod_pid),
                        )?;
                    }

                    Ok(())
                },
            };
            let ycsb_cfg = YcsbConfig {
                workload: YcsbWorkload::Custom {
                    record_count: op_count,
                    op_count,
                    read_prop,
                    update_prop,
                    insert_prop: 1.0 - read_prop - update_prop,
                },
                system: YcsbSystem::MongoDB(mongodb_config),
                ycsb_path,
                ycsb_result_file: Some(ycsb_result_file),
            };
            let mut ycsb = YcsbSession::new(ycsb_cfg);

            // Prepare.
            ycsb.start_and_load(&ushell)?;

            // Turn on kbadgerd if needed.
            if cfg.kbadgerd {
                if let Ok(mongod_pid) = ushell
                    .run(cmd!("pgrep mongod"))?
                    .stdout
                    .as_str()
                    .trim()
                    .parse::<usize>()
                {
                    ushell.run(cmd!(
                        "echo {} | sudo tee /sys/kernel/mm/kbadgerd/enabled",
                        mongod_pid
                    ))?;
                } else {
                    ushell.run(cmd!("echo \"Could not find process mongod.\""))?;
                }
            }

            // Start `perf` if needed.
            let perf_handle = if let Some((mmu_overhead_file, counters)) = mmu_overhead {
                let handle = ushell.spawn(cmd!(
                    "{}",
                    gen_perf_command_prefix(mmu_overhead_file, counters, "-p `pgrep mongod`"),
                ))?;

                // Wait for perf to start collection.
                ushell.run(
                    cmd!("while [ ! -e {} ] ; do sleep 1 ; done", mmu_overhead_file).use_bash(),
                )?;

                Some(handle)
            } else {
                None
            };

            // Run the workload.
            time!(timers, "Workload", ycsb.run(&ushell)?);

            // Make sure mongod dies
            ushell.run(cmd!("sudo pkill mongod"))?;

            // Make sure perf is done.
            if let Some(handle) = perf_handle {
                let (_, result) = handle.join();
                result?;
            }
        }

        Workload::Graph500 { scale } => {
            time!(timers, "Workload", {
                run_graph500(
                    &ushell,
                    &dir!(
                        user_home.as_str(),
                        RESEARCH_WORKSPACE_PATH,
                        ZEROSIM_GRAPH500_SUBMODULE
                    ),
                    scale,
                    output_file,
                    if cfg.damon {
                        Some(Damon {
                            damon_path: &damon_path,
                            output_path: &damon_output_path,
                            sample_interval: cfg.damon_sample_interval,
                            aggregate_interval: cfg.damon_aggr_interval,
                        })
                    } else {
                        None
                    },
                    if cfg.memtrace {
                        Some(Pintool::MemTrace {
                            pin_path: &pin_path,
                            output_path: &trace_file,
                        })
                    } else {
                        None
                    },
                    mmu_overhead,
                )?
            });
        }

        w @ Workload::Spec2017Mcf
        | w @ Workload::Spec2017Xz {
            spec_input: _,
            size: _,
        }
        | w @ Workload::Spec2017Xalancbmk { size: _ } => {
            let wkload = match w {
                Workload::Spec2017Mcf => Spec2017Workload::Mcf,
                Workload::Spec2017Xz { spec_input, size } => {
                    Spec2017Workload::Xz { spec_input, size }
                }
                Workload::Spec2017Xalancbmk { size } => Spec2017Workload::Xalancbmk { size },
                _ => unreachable!(),
            };

            time!(timers, "Workload", {
                run_hacky_spec17(
                    &ushell,
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, SPEC_2017_DIR),
                    wkload,
                    cb_wrapper_cmd,
                    mmu_overhead,
                    if cfg.perf_record {
                        Some(&trace_file)
                    } else {
                        None
                    },
                    &runtime_file,
                    [tctx.next(), tctx.next(), tctx.next(), tctx.next()],
                )?;
            });
        }

        Workload::Canneal { workload } => {
            time!(timers, "Workload", {
                run_canneal(
                    &ushell,
                    workload,
                    cb_wrapper_cmd,
                    mmu_overhead,
                    if cfg.perf_record {
                        Some(&trace_file)
                    } else {
                        None
                    },
                    &runtime_file,
                    tctx.next(),
                )?;
            });
        }

        Workload::NasCG { class } => {
            time!(timers, "Workload", {
                spawn_nas_cg(
                    &ushell,
                    &bmks_dir,
                    class,
                    Some(output_file),
                    cb_wrapper_cmd,
                    mmu_overhead,
                    &mut tctx,
                )?
                .join()
                .1?;
            });
        }
    }

    teardown(
        &ushell,
        &mut timers,
        bgctx,
        cfg.pftrace,
        cfg.mm_econ,
        cfg.mmstats,
        cfg.meminfo_periodic,
        cfg.smaps_periodic,
        cfg.damon,
        cfg.kbadgerd,
        results_dir,
        pftrace_rejected_file,
        pftrace_file,
        bpf_trace_thread,
        mmstats_file,
        badger_trap_file,
        time_file,
        sim_file,
        matches!(cfg.workload, Workload::Graph500 { .. }),
        eagerprofile_thread,
    )?;

    let glob = cfg.gen_file_name("");
    println!(
        "RESULTS: {}",
        dir!(setup00000::HOSTNAME_SHARED_RESULTS_DIR, glob)
    );

    Ok(())
}
