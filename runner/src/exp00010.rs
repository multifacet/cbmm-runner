//! Run a workload on bare-metal (e.g. AWS).
//!
//! Requires `setup00000` with the appropriate kernel. If mmstats is passed, an instrumented kernel
//! needs to be installed. If `--damon` is used, then `setup00002` with the DAMON kernel is needed.
//! If `--thp_huge_addr` is used, then `setup00002` with an instrumented kernel is needed. If
//! `--hawkeye` is used, then `setup00004` is needed to install hawkeye and related tools.

use std::fs;

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
        run_canneal, run_cloudsuite_web_serving, run_graph500, run_hacky_spec17,
        run_locality_mem_access, run_memcached_gen_data, run_mix, run_thp_ubmk, run_thp_ubmk_shm,
        run_time_loop, run_time_mmap_touch, run_ycsb_workload, spawn_nas_cg, CannealWorkload,
        Damon, LocalityMemAccessConfig, LocalityMemAccessMode, MemcachedWorkloadConfig,
        MongoDBWorkloadConfig, NasClass, Pintool, Spec2017Workload, TasksetCtx,
        TimeMmapTouchConfig, TimeMmapTouchPattern, YcsbConfig, YcsbSystem, YcsbWorkload,
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
    MongoDB {
        op_count: usize,
        read_prop: f32,
        update_prop: f32,
        tmpfs_size: Option<usize>,
    },
    Mix {
        size: usize,
    },
    Graph500 {
        scale: usize,
    },
    Spec2017Mcf,
    Spec2017Xalancbmk {
        size: usize,
    },
    Spec2017Xz {
        size: usize,
    },
    Canneal {
        workload: CannealWorkload,
    },
    CloudsuiteWebServing {
        load_scale: usize,
    },
    NasCG {
        class: NasClass,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ThpHugeAddrMode {
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

#[derive(Clone, Debug)]
enum ThpHugeAddrProcess {
    /// Use for processes that have already started.
    Pid(usize),

    /// Use for processes that have not started yet.
    Command(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    workload: Workload,

    #[name(self.eager)]
    eager: bool,

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
    badger_trap: bool,
    kbadgerd: bool,
    kbadgerd_sleep_interval: Option<usize>,
    mm_econ: bool,
    mm_econ_benefit_file: Option<String>,
    enable_aslr: bool,
    pftrace: Option<usize>,
    asynczero: bool,
    hawkeye: bool,

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
            (about: "Run the `memcached` workload.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload (e.g. 500)")
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
        )
        (@subcommand mix =>
            (about: "Run the `mix` workload.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload (e.g. 500)")
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
             (@arg RAND_NUM_INPUTS: --rand_num_inputs requires[RAND]
              "Have a random number of inputs per net in the canneal input file.")
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
        (@subcommand cloudsuite =>
            (about: "Run a Cloudsuite benchmark.")
            (@subcommand web_serving =>
                (about: "Run the Web Serving benchmark.")
                (@arg LOAD_SCALE: +takes_value {validator::is::<usize>}
                 "Use the given number of concurrent clients.")
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
             "Set the THP huge_addr setting to the given value and otherwise disable THP.")
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
        (@arg BADGER_TRAP: --badger_trap
         "Use badger_trap to measure TLB misses.")
        (@arg KBADGERD: --kbadgerd
         "Use kbadgerd to measure TLB misses.")
        (@arg KBADGERD_SLEEP_INTERVAL: --kbadgerd_sleep_interval
         +takes_value {validator::is::<usize>} requires[KBADGERD]
         "Sets the sleep_interval for kbadgerd.")
        (@arg MM_ECON: --mm_econ
         "Enable mm_econ.")
        (@arg MM_ECON_BENEFIT_FILE: --mm_econ_benefit_file +takes_value
         requires[MM_ECON]
         "Import a list of conditions for a memory mapping and the benefit of that mapping being \
         huge. The list taken from the csv file specified in this argument. The file should have the format\n\
         SECTION,MISSES,CONSTRAINTS\n\
         where SECTION can be code, data, heap, or mmap,\n\
         CONSTRAINTS is an unbounded list of QUANTITY,COMP,VALUE\n\
         QUANTITY can be section_off, addr, len, prot, flags, fd, or off\n\
         COMP can be >, <, or =.")
        (@arg ENABLE_ASLR: --enable_aslr
         "Enable ASLR.")
        (@arg PFTRACE: --pftrace
         "Enable page fault tracing (requires an instrumented kernel).")
        (@arg PFTRACE_THRESHOLD: --pftrace_threshold
         +takes_value {validator::is::<usize>} requires[PFTRACE]
         "Sets the pftrace_threshold for minimum latency to be sampled.")
        (@arg ASYNCZERO: --asynczero
         "Enable async pre-zeroing.")
        (@arg HAWKEYE: --hawkeye
         conflicts_with[MM_ECON KBADGERD THP_HUGE_ADDR PFTRACE EAGER MMSTATS]
         "Turn on HawkEye (ASPLOS '19).")
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
            }
        }

        ("mix", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();

            Workload::Mix { size }
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

            let wk = match sub_m.value_of("WHICH").unwrap() {
                "mcf" => Workload::Spec2017Mcf,
                "xalancbmk" => Workload::Spec2017Xalancbmk { size },
                "xz" => Workload::Spec2017Xz { size },
                _ => panic!("Unknown spec workload"),
            };

            if size != 0 {
                let size_implemented = match &wk {
                    Workload::Spec2017Xz { size: _ } => true,
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
                let rand_num_inputs = if sub_m.is_present("RAND_NUM_INPUTS") {
                    true
                } else {
                    false
                };
                CannealWorkload::Rand {
                    size,
                    uniform_dist,
                    rand_num_inputs,
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

        ("cloudsuite", Some(sub_m)) => match sub_m.subcommand() {
            ("web_serving", Some(sub_m)) => {
                let load_scale = sub_m
                    .value_of("LOAD_SCALE")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                Workload::CloudsuiteWebServing { load_scale }
            }

            _ => unreachable!(),
        },

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
    let badger_trap = sub_m.is_present("BADGER_TRAP");
    let kbadgerd = sub_m.is_present("KBADGERD");
    let kbadgerd_sleep_interval = sub_m
        .value_of("KBADGERD_SLEEP_INTERVAL")
        .map(|s| s.parse::<usize>().unwrap());
    let mm_econ = sub_m.is_present("MM_ECON");
    let mm_econ_benefit_file = sub_m
        .is_present("MM_ECON_BENEFIT_FILE")
        .then(|| String::from(sub_m.value_of("MM_ECON_BENEFIT_FILE").unwrap()));
    let enable_aslr = sub_m.is_present("ENABLE_ASLR");
    let pftrace = sub_m.is_present("PFTRACE").then(|| {
        sub_m
            .value_of("PFTRACE_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap())
            .unwrap_or(100000)
    });
    let asynczero = sub_m.is_present("ASYNCZERO");
    let hawkeye = sub_m.is_present("HAWKEYE");

    // FIXME: thp_ubmk_shm doesn't support thp_huge_addr at the moment. It's possible to implement
    // it, but I haven't yet... The implementation would look as follows: thp_ubmk_shm would take
    // an argument for which pages to use huge pages, and it would map those backed by the
    // hugetlbfs. The remaining pages would be backed by normal shm.
    if let Workload::ThpUbmkShm { .. } = workload {
        if sub_m.is_present("THP_UBMK_DIR") {
            unimplemented!("thp_huge_addr isn't supported by thp_ubmk_shm yet.");
        }
    }

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

    let (load_misses, store_misses) = {
        let suffix = crate::cpu::page_walk_perf_counter_suffix(&ushell)?;
        (
            format!("dtlb_load_misses.{}", suffix),
            format!("dtlb_store_misses.{}", suffix),
        )
    };
    let perf_counters: Vec<String> = sub_m.values_of("PERF_COUNTER").map_or_else(
        || {
            vec![
                load_misses,
                store_misses,
                "dtlb_load_misses.miss_causes_a_walk".into(),
                "dtlb_store_misses.miss_causes_a_walk".into(),
                "cpu_clk_unhalted.thread_any".into(),
                "inst_retired.any".into(),
                "faults".into(),
                "migrations".into(),
                "cs".into(),
            ]
        },
        |counters| counters.map(Into::into).collect(),
    );

    let cfg = Config {
        exp: (10, "bare_metal".into()),

        workload,

        eager,

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
        badger_trap,
        kbadgerd,
        kbadgerd_sleep_interval,
        mm_econ,
        mm_econ_benefit_file,
        enable_aslr,
        pftrace,
        asynczero,
        hawkeye,

        username: login.username.into(),
        host: login.hostname.into(),

        local_git_hash,
        remote_git_hash,

        remote_research_settings,

        timestamp: Timestamp::now(),
    };

    run_inner(&login, &cfg)
}

fn run_inner<A>(login: &Login<A>, cfg: &Config) -> Result<(), failure::Error>
where
    A: std::net::ToSocketAddrs + std::fmt::Display + std::fmt::Debug + Clone,
{
    // Reboot
    initial_reboot_no_vagrant(&login)?;

    // Connect
    let ushell = connect_and_setup_host_only(&login)?;

    let user_home = &get_user_home_dir(&ushell)?;
    let zerosim_exp_path = &dir!(
        user_home,
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_EXPERIMENTS_SUBMODULE
    );

    // Start asynczeroing daemon and throttle it up a bit.
    if cfg.asynczero {
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
    if cfg.hawkeye {
        ushell.run(cmd!(
            "sudo insmod HawkEye/kbuild/hawkeye_modules/async-zero/asynczero.ko"
        ))?;
    }

    // Turn of ASLR
    if cfg.enable_aslr {
        // ASLR is enabled by default on startup, so this probably isn't
        // necessary, but it's good to be explicit.
        crate::enable_aslr(&ushell)?;
    } else {
        crate::disable_aslr(&ushell)?;
    }

    // Allow `perf` as any user
    crate::perf_for_all(&ushell)?;

    // Turn on/off compaction and force it to happen if needed
    if matches!(cfg.workload, Workload::ThpUbmkShm { .. }) {
        crate::turn_on_thp(
            &ushell,
            /* enabled */ "never",
            /* defrag */ "never",
            cfg.transparent_hugepage_khugepaged_defrag,
            cfg.transparent_hugepage_khugepaged_alloc_sleep_ms,
            cfg.transparent_hugepage_khugepaged_scan_sleep_ms,
        )?;

        // Reserve a huge page and use it for a hugetlbfs.
        ushell.run(cmd!("sudo sysctl vm.nr_hugepages=4"))?;
        ushell.run(cmd!("sudo mkdir -p /mnt/huge"))?;
        ushell.run(cmd!(
            "sudo mount -t hugetlbfs -o uid=`id -u`,gid=`id -g`,pagesize=2M,size=8M none /mnt/huge"
        ))?;
    } else {
        crate::turn_on_thp(
            &ushell,
            &cfg.transparent_hugepage_enabled,
            &cfg.transparent_hugepage_defrag,
            cfg.transparent_hugepage_khugepaged_defrag,
            cfg.transparent_hugepage_khugepaged_alloc_sleep_ms,
            cfg.transparent_hugepage_khugepaged_scan_sleep_ms,
        )?;
    }

    // Turn of NUMA balancing
    crate::set_auto_numa(&ushell, false /* off */)?;

    // Collect timers on VM
    let mut timers = vec![];

    let (output_file, params_file, time_file, sim_file) = cfg.gen_standard_names();
    let results_dir = &dir!(user_home, setup00000::HOSTNAME_SHARED_RESULTS_DIR);
    let mmstats_file = cfg.gen_file_name("mmstats");
    let meminfo_file = cfg.gen_file_name("meminfo");
    let smaps_file = cfg.gen_file_name("smaps");
    let mmap_tracker_file = dir!(results_dir, cfg.gen_file_name("mmap"));
    let damon_output_path = cfg.gen_file_name("damon");
    let damon_output_path = dir!(results_dir, damon_output_path);
    let bmks_dir = &dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_BENCHMARKS_DIR);
    let damon_path = dir!(bmks_dir, DAMON_PATH);
    let pin_path = dir!(
        user_home,
        RESEARCH_WORKSPACE_PATH,
        ZEROSIM_MEMBUFFER_EXTRACT_SUBMODULE,
        "pin"
    );
    let trace_file = dir!(results_dir, cfg.gen_file_name("trace"));
    let mmu_overhead_file = dir!(results_dir, cfg.gen_file_name("mmu"));
    let ycsb_result_file = &dir!(results_dir, cfg.gen_file_name("ycsb"));
    let badger_trap_file = dir!(results_dir, cfg.gen_file_name("bt"));
    let pftrace_file = dir!(results_dir, cfg.gen_file_name("pftrace"));
    let pftrace_rejected_file = dir!(results_dir, cfg.gen_file_name("rejected"));
    let mmap_filter_csv_name = dir!(results_dir, cfg.gen_file_name("mmap-filters.csv"));
    let runtime_file = dir!(results_dir, cfg.gen_file_name("runtime"));

    let params = serde_json::to_string(&cfg)?;

    ushell.run(cmd!(
        "echo '{}' > {}",
        escape_for_bash(&params),
        dir!(results_dir, params_file)
    ))?;

    let swapnil_path = dir!(bmks_dir, ZEROSIM_SWAPNIL_PATH);
    let eager = if cfg.eager {
        Some(swapnil_path.as_str())
    } else {
        None
    };
    let mmu_overhead = if cfg.mmu_overhead {
        Some((mmu_overhead_file.as_str(), cfg.perf_counters.as_slice()))
    } else {
        None
    };

    let cores = crate::get_num_cores(&ushell)?;
    let mut tctx = TasksetCtx::new(cores);

    if cfg.mmstats {
        // Print the current numbers, 'cause why not?
        ushell.run(cmd!("tail /proc/mm_*"))?;

        // Writing to any of the params will reset the plot.
        ushell.run(cmd!(
            "for h in /proc/mm_*_min ; do echo $h ; echo 0 | sudo tee $h ; done"
        ))?;
    }

    // Maybe collect meminfo
    let mut bgctx = BackgroundContext::new(&ushell);
    if cfg.meminfo_periodic {
        bgctx.spawn(BackgroundTask {
            name: "meminfo",
            period: PERIOD,
            cmd: format!(
                "cat /proc/meminfo | tee -a {}",
                dir!(results_dir, &meminfo_file),
            ),
            ensure_started: dir!(results_dir, &meminfo_file),
        })?;
    }

    let nas_proc_name = if let Workload::NasCG { class } = cfg.workload {
        Some(format!("cg.{}.x", class))
    } else {
        None
    };
    let proc_name = match cfg.workload {
        Workload::TimeLoop { .. } => Some("time_loop"),
        Workload::LocalityMemAccess { .. } => Some("locality_mem_access"),
        Workload::TimeMmapTouch { .. } => Some("time_mmap_touch"),
        Workload::ThpUbmk { .. } => Some("ubmk"),
        Workload::ThpUbmkShm { .. } => Some("ubmk-shm"),
        Workload::Memcached { .. } => Some("memcached"),
        Workload::MongoDB { .. } => Some("mongod"),
        Workload::Graph500 { .. } => Some("graph500"),
        Workload::Spec2017Xz { .. } => Some("xz_s"),
        Workload::Spec2017Mcf { .. } => Some("mcf_s"),
        Workload::Spec2017Xalancbmk { .. } => Some("xalancbmk_s"),
        Workload::Canneal { .. } => Some("canneal"),
        Workload::NasCG { .. } => nas_proc_name.as_ref().map(String::as_str),

        Workload::Mix { .. } => None,
        Workload::CloudsuiteWebServing { .. } => None,
    };
    let proc_name_grep = match cfg.workload {
        Workload::Mix { .. } => "'redis-server|matrix_mult2|memhog'",
        Workload::CloudsuiteWebServing { .. } => "'memcached|mysqld|hhvm|hh_single_compile|nginx'",
        _ => proc_name.unwrap(),
    };

    if cfg.smaps_periodic {
        match cfg.workload {
            Workload::Mix { .. } | Workload::CloudsuiteWebServing { .. } => {
                panic!("Doesn't make sense to get smaps of multi-process workload!")
            }
            _ => {}
        }

        bgctx.spawn(BackgroundTask {
            name: "smaps",
            period: PERIOD,
            cmd: format!(
                "((sudo cat /proc/`pgrep -x {}  | sort -n | head -n1`/smaps) || echo none) | tee -a {}",
                proc_name_grep,
                dir!(
                    results_dir,
                    &smaps_file
                ),
            ),
            ensure_started: dir!(
                results_dir,
                &smaps_file
            ),
        })?;
    }

    if cfg.mmap_tracker {
        // This is needed for BPF to compile, but we don't want it enabled all
        // of the time because it interferes with gcc and g++
        let enable_bpf_cmd = "source scl_source enable devtoolset-7 llvm-toolset-7";

        ushell.spawn(cmd!(
            "{}; \
            sudo {}/bmks/mmap_tracker.py -c {} | tee {}",
            enable_bpf_cmd,
            &dir!(user_home, RESEARCH_WORKSPACE_PATH),
            proc_name.unwrap(),
            mmap_tracker_file
        ))?;
        // Wait some time for the BPF validator to do its job
        println!("Waiting 10s for BPF validator...");
        ushell.run(cmd!("sleep 10"))?;
    }

    // Set `huge_addr` if needed.
    if let Some(ref huge_addr) = cfg.transparent_hugepage_huge_addr {
        // We need to truncate the name to 15 characters because Linux will truncate current->comm
        // to 15 characters. In order for them to match we truncate it here...
        let proc_name = proc_name.unwrap();
        let proc_name_trunc = proc_name.get(..15).unwrap_or(proc_name);
        turn_on_huge_addr(
            &ushell,
            huge_addr.clone(),
            ThpHugeAddrProcess::Command(proc_name_trunc.into()),
        )?;
    }

    // Turn on BadgerTrap if needed
    if cfg.badger_trap {
        ushell.run(cmd!(
            "{}/0sim-workspace/bmks/BadgerTrap/badger-trap name {}",
            user_home,
            proc_name.unwrap()
        ))?;
    }

    // Turn on mm_econ if needed.
    if cfg.mm_econ {
        ushell.run(cmd!("echo 1 | sudo tee /sys/kernel/mm/mm_econ/enabled"))?;
    }

    // Generate the cb_wrapper command if necessary
    let cb_wrapper_cmd = if let Some(filename) = &cfg.mm_econ_benefit_file {
        // Do some sanity checking first...
        match cfg.workload {
            Workload::TimeLoop { .. }
            | Workload::LocalityMemAccess { .. }
            | Workload::TimeMmapTouch { .. }
            | Workload::Graph500 { .. }
            | Workload::CloudsuiteWebServing { .. }
            | Workload::NasCG { .. } => unimplemented!(),

            Workload::ThpUbmk { .. }
            | Workload::ThpUbmkShm { .. }
            | Workload::Memcached { .. }
            | Workload::MongoDB { .. }
            | Workload::Spec2017Mcf
            | Workload::Spec2017Xalancbmk { .. }
            | Workload::Spec2017Xz { .. }
            | Workload::Canneal { .. }
            | Workload::Mix { .. } => {}
        }

        println!("Reading mm_econ benefit file: {}", filename);
        let filter_csv = fs::read_to_string(filename)?;
        let cb_wrapper_file = dir!(bmks_dir, "cb_wrapper");

        // Be sure to save the contents of the mmap_filter in the results
        // so we can reference them later
        ushell.run(cmd!("echo -n '{}' > {}", filter_csv, mmap_filter_csv_name))?;

        Some(format!("{} {}", cb_wrapper_file, mmap_filter_csv_name))
    } else {
        None
    };
    let cb_wrapper_cmd = cb_wrapper_cmd.as_ref().map(|s| s.as_str());

    if cfg.mm_econ {
        ushell.run(cmd!("cat /sys/kernel/mm/mm_econ/stats"))?;
    }

    if let Some(threshold) = cfg.pftrace {
        ushell.run(cmd!("echo 1 | sudo tee /proc/pftrace_enable"))?;
        ushell.run(cmd!(
            "echo {} | sudo tee /proc/pftrace_threshold",
            threshold
        ))?;
    }

    // Turn on kbadgerd if needed.
    if cfg.kbadgerd {
        ushell.run(cmd!(
            "ls /sys/kernel/mm/kbadgerd || \
            sudo insmod $(ls -t1 kernel-*/kbuild/vmlinux | head -n1 | cut -d / -f1)/kbuild/mm/kbadgerd/kbadgerd.ko"
        ))?;
    }
    if let Some(sleep_interval) = cfg.kbadgerd_sleep_interval {
        ushell.run(cmd!(
            "echo {} | sudo tee /sys/kernel/mm/kbadgerd/sleep_interval",
            sleep_interval
        ))?;
    }

    let _kbadgerd_thread = if cfg.kbadgerd
        && !matches!(
            cfg.workload,
            Workload::Memcached { .. } | Workload::MongoDB { .. }
        ) {
        Some(ushell.spawn(cmd!(
            "while ! [ `pgrep -x {}` ] ; do echo 'Waiting for process {}' ; done ; \
             echo `pgrep -x {}` | sudo tee /sys/kernel/mm/kbadgerd/enabled",
            proc_name_grep,
            proc_name_grep,
            proc_name_grep,
        ))?)
    } else {
        None
    };

    if cfg.asynczero || cfg.hawkeye {
        // Wait a bit for zeroing daemons to warm up a bit.
        std::thread::sleep(std::time::Duration::from_secs(10));

        ushell.run(cmd!(
            "sudo cat /sys/module/asynczero/parameters/pages_zeroed"
        ))?;
    }
    if cfg.asynczero {
        ushell.run(cmd!(
            "echo 0 | sudo tee /sys/module/asynczero/parameters/mode"
        ))?;
        // NOTE: here the count is in individual 4KB pages.
        ushell.run(cmd!(
            "echo 100 | sudo tee /sys/module/asynczero/parameters/count"
        ))?;
    }
    if cfg.hawkeye {
        // Just use the default parameters of the module...
        //
        // NOTE: here the count is in terms of compond pages, which could be of any
        // power-of-two size.
        //ushell.run(cmd!(
        //    "echo 10 | sudo tee /sys/module/asynczero/parameters/count"
        //))?;
    }

    // Turn on hawkeye bloat removal thread and profiler if needed.
    if cfg.hawkeye {
        if let Some(proc_name) = proc_name {
            ushell.run(cmd!(
                "sudo insmod HawkEye/kbuild/hawkeye_modules/bloat_recovery/remove.ko \
                 debloat_comm={}",
                proc_name
            ))?;
            // 120s sleep between debloating, according to Ashish Panwar.
            ushell.run(cmd!(
                "echo 120 | sudo tee /sys/module/remove/parameters/sleep"
            ))?;

            // Use default interval of 10s -- Ashish Panwar.
            ushell.run(cmd!(
                "./x86-MMU-Profiler/global_profile -d -p {} {}",
                proc_name,
                match cpu_family_model(&ushell)? {
                    Processor::Intel(IntelX86Model::SkyLakeServer) => "-f skylakesp",
                    Processor::Intel(IntelX86Model::HaswellConsumer) => "-f haswell",

                    _ => unimplemented!(),
                }
            ))?;

            // promotion_metric: default 0 = HawkEye-PMU; 2 = HawkEye-G.
            // scan_sleep_millisecs: 1000 for Fig 8 (HawkEye paper) experiments.
        } else {
            panic!("HawkEye with nameless processes...");
        }
    }

    // Run the workload.
    match cfg.workload {
        Workload::TimeLoop { n } => {
            time!(
                timers,
                "Workload",
                run_time_loop(
                    &ushell,
                    zerosim_exp_path,
                    n,
                    &dir!(results_dir, output_file),
                    eager,
                    &mut tctx,
                )?
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
                        eager,
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
                        eager,
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
                        output_file: Some(&dir!(results_dir, output_file)),
                        eager,
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
                        output_file: Some(&dir!(results_dir, output_file)),
                        eager,
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

        Workload::MongoDB {
            op_count,
            read_prop,
            update_prop,
            tmpfs_size,
        } => {
            let ycsb_path = &dir!(bmks_dir, "YCSB");
            let mongodb_config = MongoDBWorkloadConfig {
                bmks_dir,
                db_dir: &dir!(user_home, "mongodb"),
                tmpfs_size,
                cache_size_mb: None,
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
                callback: || {
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
                    Ok(())
                },
            };

            time!(
                timers,
                "Workload",
                run_ycsb_workload::<spurs::SshError, _, _>(&ushell, ycsb_cfg,)?
            );
        }

        Workload::Mix { size } => {
            let freq = get_cpu_freq(&ushell)?;

            time!(timers, "Workload", {
                run_mix(
                    &ushell,
                    zerosim_exp_path,
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_METIS_SUBMODULE),
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_MEMHOG_SUBMODULE),
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_NULLFS_SUBMODULE),
                    &dir!(user_home, RESEARCH_WORKSPACE_PATH, REDIS_CONF),
                    cb_wrapper_cmd,
                    freq,
                    size,
                    eager,
                    &mut tctx,
                    &runtime_file,
                )?
            });
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
                    &dir!(results_dir, output_file),
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
                )?
            });
        }

        w @ Workload::Spec2017Mcf
        | w @ Workload::Spec2017Xz { size: _ }
        | w @ Workload::Spec2017Xalancbmk { size: _ } => {
            let wkload = match w {
                Workload::Spec2017Mcf => Spec2017Workload::Mcf,
                Workload::Spec2017Xz { size } => Spec2017Workload::Xz { size },
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
                    Some(&dir!(results_dir, output_file)),
                    cb_wrapper_cmd,
                    mmu_overhead,
                    eager,
                    &mut tctx,
                )?
                .join()
                .1?;
            });
        }

        Workload::CloudsuiteWebServing { load_scale } => {
            time!(timers, "Workload", {
                run_cloudsuite_web_serving(&ushell, load_scale, &runtime_file)?;
            });
        }
    }

    if cfg.pftrace.is_some() {
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

    if cfg.mm_econ {
        ushell.run(cmd!("cat /sys/kernel/mm/mm_econ/stats"))?;
    }

    if cfg.mmstats {
        let mmstats_file = dir!(results_dir, &mmstats_file);

        ushell.run(cmd!("tail /proc/mm_* | tee {}", mmstats_file))?;
        ushell.run(cmd!("cat /proc/meminfo | tee -a {}", mmstats_file))?;
        ushell.run(cmd!("cat /proc/vmstat | tee -a {}", mmstats_file))?;

        if cfg.mm_econ {
            ushell.run(cmd!(
                "cat /sys/kernel/mm/mm_econ/stats | tee -a {}",
                mmstats_file
            ))?;
        }
    }

    if cfg.meminfo_periodic || cfg.smaps_periodic {
        time!(
            timers,
            "Waiting for data collectioned threads to halt",
            bgctx.notify_and_join_all()?
        );
    }

    // Tell damon to write data, if needed. (Graph500 waits for damon to finish, so we don't need
    // to do it again).
    if cfg.damon && !matches!(cfg.workload, Workload::Graph500 { .. }) {
        time!(timers, "Waiting for DAMON to flush data buffers", {
            ushell.run(cmd!(
                "echo off | sudo tee /sys/kernel/debug/damon/monitor_on"
            ))?;
        })
    }

    // Extract relevant data from dmesg for BadgerTrap, if needed.
    if cfg.badger_trap {
        // We need to ensure the relevant process has terminated.
        ushell.run(cmd!("pkill -9 {} || echo 'already dead'", proc_name_grep))?;

        // We wait until the results have been written...
        while ushell
            .run(cmd!("dmesg | grep -q 'BadgerTrap: END Statistics'"))
            .is_err()
        {
            std::thread::sleep(std::time::Duration::from_secs(10));
        }

        ushell.run(cmd!(
            "dmesg | grep 'BadgerTrap:' | tee {}",
            badger_trap_file
        ))?;
    }

    // Extract relevant data from dmesg for kbadgerd, if needed.
    if cfg.kbadgerd {
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
        "echo -e '{}' > {}",
        crate::timings_str(timers.as_slice()),
        dir!(results_dir, time_file)
    ))?;

    crate::gen_standard_host_output(&sim_file, &ushell)?;

    let glob = cfg.gen_file_name("");
    println!(
        "RESULTS: {}",
        dir!(setup00000::HOSTNAME_SHARED_RESULTS_DIR, glob)
    );

    Ok(())
}

fn turn_on_huge_addr(
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
