//! Run a multi-process workload on bare-metal (e.g. AWS).
//!
//! Requires `setup00000` with the appropriate kernel. If mmstats is passed, an instrumented kernel
//! needs to be installed. If `--damon` is used, then `setup00002` with the DAMON kernel is needed.
//! If `--thp_huge_addr` is used, then `setup00002` with an instrumented kernel is needed. If
//! `--hawkeye` is used, then `setup00004` is needed to install hawkeye and related tools.

use std::{collections::HashMap, fs};

use clap::clap_app;

use crate::{
    cli::validator,
    dir,
    exp_0sim::*,
    get_cpu_freq,
    multiworkloads::{
        CloudsuiteWebServingWorkload, CloudsuiteWebServingWorkloadKey, MixWorkload, MixWorkloadKey,
        MultiProcessWorkload, WorkloadKey,
    },
    output::{Parametrize, Timestamp},
    paths::*,
    time,
    workloads::gen_perf_command_prefix,
};

use serde::{Deserialize, Serialize};

use spurs::{cmd, Execute, SshShell};

use crate::exp00010::{turn_on_huge_addr, ThpHugeAddrMode, ThpHugeAddrProcess};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
enum Workload {
    Mix { size: usize },
    CloudsuiteWebServing { load_scale: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize, Parametrize)]
struct Config {
    #[name]
    exp: (usize, String),

    #[name]
    workload: Workload,

    mmstats: bool,
    meminfo_periodic: bool,
    pftrace: Option<usize>,

    instrumented_process: Option<String>,
    mmu_overhead: bool,
    perf_counters: Option<Vec<String>>,
    smaps_periodic: bool,
    mmap_tracker: bool,
    badger_trap: bool,
    kbadgerd: bool,
    kbadgerd_sleep_interval: Option<usize>,

    mm_econ: bool,
    enable_aslr: bool,
    asynczero: bool,
    hawkeye: Option<String>,
    #[name(self.fragmentation.is_some())]
    fragmentation: Option<usize>,

    #[name(self.transparent_hugepage_enabled == "never")]
    transparent_hugepage_enabled: String,
    transparent_hugepage_defrag: String,
    transparent_hugepage_khugepaged_defrag: usize,
    transparent_hugepage_khugepaged_alloc_sleep_ms: usize,
    transparent_hugepage_khugepaged_scan_sleep_ms: usize,

    eager: Option<Vec<String>>,
    #[name(self.transparent_hugepage_huge_addr.is_some())]
    transparent_hugepage_huge_addr: Option<(ThpHugeAddrMode, ThpHugeAddrProcess)>,
    mm_econ_benefits: Vec<(String, String)>,

    username: String,
    host: String,

    local_git_hash: String,
    remote_git_hash: String,

    remote_research_settings: std::collections::BTreeMap<String, String>,

    #[timestamp]
    timestamp: Timestamp,
}

pub fn cli_options() -> clap::App<'static, 'static> {
    let app = clap_app! { exp00012 =>
        (about: "Run experiment 00012. Requires `sudo`.")
        (@setting ArgRequiredElseHelp)
        (@setting DisableVersion)
        (@arg HOSTNAME: +required +takes_value
         "The domain name of the remote (e.g. c240g2-031321.wisc.cloudlab.us:22)")
        (@arg USERNAME: +required +takes_value
         "The username on the remote (e.g. markm)")

        // Workloads
        (@subcommand mix =>
            (about: "Run the `mix` workload.")
            (@arg SIZE: +required +takes_value {validator::is::<usize>}
             "The number of GBs of the workload (e.g. 500)")
        )
        (@subcommand cloudsuite =>
            (about: "Run a Cloudsuite benchmark.")
            (@subcommand web_serving =>
                (about: "Run the Web Serving benchmark.")
                (@arg LOAD_SCALE: +takes_value {validator::is::<usize>}
                 "Use the given number of concurrent clients.")
            )
        )

        // Global Instrumentation
        (@arg MMSTATS: --memstats
         "Collect latency histograms for memory management ops; \
          requires a kernel that has instrumentation.")
        (@arg MEMINFO_PERIODIC: --meminfo_periodic
         "Collect /proc/meminfo data periodically.")
        (@arg PFTRACE: --pftrace
         "Enable page fault tracing (requires an instrumented kernel).")
        (@arg PFTRACE_THRESHOLD: --pftrace_threshold
         +takes_value {validator::is::<usize>} requires[PFTRACE]
         "Sets the pftrace_threshold for minimum latency to be sampled (default 10000).")

        // Single-process instrumentation
        (@arg INSTRUMENT_PROCESS: --instrument +takes_value
         "Specifies the \"instrumented process\". Single-process instrumentation is applied \
         to the process with the given name.")
        (@arg MMU_OVERHEAD: --mmu_overhead requires[INSTRUMENT_PROCESS]
         "Collect MMU overhead stats via perf counters for the instrumented process.")
        (@arg PERF_COUNTERS: --perf_counter +takes_value ... number_of_values(1)
         requires[MMU_OVERHEAD]
         "Collect the given counters instead of the default ones.")
        (@arg SMAPS_PERIODIC: --smaps_periodic requires[INSTRUMENT_PROCESS]
         "Collect /proc/[PID]/smaps data periodically for the instrumented process.")
        (@arg MMAP_TRACKER: --mmap_tracker requires[INSTRUMENT_PROCESS]
         "Record stats for mmap calls for the main workload process.")
        (@arg BADGER_TRAP: --badger_trap requires[INSTRUMENT_PROCESS]
         "Use badger_trap to measure TLB misses.")
        (@arg KBADGERD: --kbadgerd requires[INSTRUMENT_PROCESS]
         "Use kbadgerd to measure TLB misses.")
        (@arg KBADGERD_SLEEP_INTERVAL: --kbadgerd_sleep_interval
         +takes_value {validator::is::<usize>} requires[KBADGERD]
         "Sets the sleep_interval for kbadgerd.")

        // Global environmental settings
        (@arg DISABLE_THP: --disable_thp
         conflicts_with[THP_HUGE_ADDR THP_HUGE_ADDR_RANGES]
         "Disable THP completely.")
        (@arg ENABLE_ASLR: --enable_aslr
         "Enable ASLR.")
        (@arg ASYNCZERO: --asynczero
         "Enable async pre-zeroing.")
        (@arg HAWKEYE: --hawkeye
         conflicts_with[MM_ECON KBADGERD THP_HUGE_ADDR THP_HUGE_ADDR_RANGES
                        PFTRACE EAGER MMSTATS ASYNCZERO DISABLE_THP]
         requires[HAWKEYE_BLOAT_PROC]
         "Turn on HawkEye (ASPLOS '19).")
        (@arg MM_ECON: --mm_econ conflicts_with[HAWKEYE]
         "Enable mm_econ.")
        (@arg FRAGMENTATION: --fragmentation +takes_value {validator::is::<usize>}
         "Fragment the given percentage of memory. Must be an integer between 0 and 100. \
          This will consume a bit of memory, as there is a daemon that holds on to a bit \
          of memory to fragment it.")

        // Per-process environmental settings
        (@arg EAGER: --eager +takes_value ...
         "Use eager paging for the given processes (by name); \
          requires a kernel that has eager paging.")
        (@arg THP_HUGE_ADDR: --thp_huge_addr +takes_value number_of_values(2)
         conflicts_with[THP_HUGE_ADDR_RANGES]
         "For the specified process, set the THP huge_addr setting to the given \
          value and disable THP for all other memory regions and processes. This \
          flag should be followed by two values: a process name and an address in hex, \
          in that order. This can only be specified for a single process.")
        (@arg THP_HUGE_ADDR_RANGES: --thp_huge_addr_ranges +takes_value min_values(3) ...
         conflicts_with[THP_HUGE_ADDR]
         "For the specified process, make all pages in the given range(s) huge. \
          Pass values as a process name followed by space-separated integers in \
          hex: PROCESSNAME START END START END ..., where START is inclusive, and END is \
          exclusive.")
        (@arg THP_HUGE_ADDR_LE: --thp_huge_addr_le
            requires[THP_HUGE_ADDR] conflicts_with[THP_HUGE_ADDR_GE]
            "Make all pages <=THP_HUGE_ADDR huge.")
        (@arg THP_HUGE_ADDR_GE: --thp_huge_addr_ge
            requires[THP_HUGE_ADDR] conflicts_with[THP_HUGE_ADDR_LE]
            "Make all pages >=THP_HUGE_ADDR huge.")
        (@arg MM_ECON_BENEFIT_PER_PROC: --mm_econ_benefits +takes_value ...
         requires[MM_ECON] number_of_values(2)
         "Set a benefits file for the given process (can be specified multiple times). Each \
          occurence of this flag should be followed by two arguments: a process name and file. \
          Each file should be a CSV containing a list of mmap filters in the format:\n\
          SECTION,MISSES,CONSTRAINTS\n\
          where SECTION can be code, data, heap, or mmap,\n\
          CONSTRAINTS is an unbounded list of QUANTITY,COMP,VALUE\n\
          QUANTITY can be section_off, addr, len, prot, flags, fd, or off\n\
          COMP can be >, <, or =.")
        (@arg HAWKEYE_BLOAT_PROC: --hawkeye_debloat +takes_value
         requires[HAWKEYE]
         "The name of the process to use with Hawkeye debloating.")
    };

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

fn parse_thp_huge_addr_cli(
    sub_m: &clap::ArgMatches<'_>,
) -> Result<Option<(ThpHugeAddrMode, ThpHugeAddrProcess)>, failure::Error> {
    Ok(if let Some(mut args) = sub_m.values_of("THP_HUGE_ADDR") {
        let proc_name = ThpHugeAddrProcess::from_name(args.next().unwrap().to_owned());
        let addr = args.next().unwrap();

        // Assert validation...
        if let Err(e) = is_huge_page_addr_hex(addr.into()) {
            failure::bail!(e);
        }

        let addr = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap();

        if sub_m.is_present("THP_HUGE_ADDR_LE") {
            Some((ThpHugeAddrMode::Less { addr }, proc_name))
        } else if sub_m.is_present("THP_HUGE_ADDR_GE") {
            Some((ThpHugeAddrMode::Greater { addr }, proc_name))
        } else {
            Some((ThpHugeAddrMode::Equal { addr }, proc_name))
        }
    } else if let Some(ranges) = sub_m.values_of("THP_HUGE_ADDR_RANGES") {
        let mut ranges = ranges.collect::<Vec<_>>();
        let proc_name = ThpHugeAddrProcess::from_name(ranges.remove(0).to_owned());

        // Do some sanity checking.
        if ranges.len() % 2 != 0 {
            failure::bail!(
                "Odd number of end points for THP_HUGE_ADDR_RANGES. Missing an endpoint."
            );
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

        Some((ThpHugeAddrMode::Ranges { ranges }, proc_name))
    } else {
        None
    })
}

pub fn run(sub_m: &clap::ArgMatches<'_>) -> Result<(), failure::Error> {
    let login = Login {
        username: sub_m.value_of("USERNAME").unwrap(),
        hostname: sub_m.value_of("HOSTNAME").unwrap(),
        host: sub_m.value_of("HOSTNAME").unwrap(),
    };

    let workload = match sub_m.subcommand() {
        ("mix", Some(sub_m)) => {
            let size = sub_m.value_of("SIZE").unwrap().parse::<usize>().unwrap();

            Workload::Mix { size }
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

    let mmstats = sub_m.is_present("MMSTATS");
    let meminfo_periodic = sub_m.is_present("MEMINFO_PERIODIC");
    let pftrace = sub_m.is_present("PFTRACE").then(|| {
        sub_m
            .value_of("PFTRACE_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap())
            .unwrap_or(100000)
    });

    let instrumented_process = sub_m.value_of("INSTRUMENT_PROCESS").map(str::to_owned);
    let mmu_overhead = sub_m.is_present("MMU_OVERHEAD");
    let perf_counters: Option<Vec<String>> = sub_m
        .values_of("PERF_COUNTERS")
        .map(|counters| counters.map(Into::into).collect());
    let smaps_periodic = sub_m.is_present("SMAPS_PERIODIC");
    let mmap_tracker = sub_m.is_present("MMAP_TRACKER");
    let badger_trap = sub_m.is_present("BADGER_TRAP");
    let kbadgerd = sub_m.is_present("KBADGERD");
    let kbadgerd_sleep_interval = sub_m
        .value_of("KBADGERD_SLEEP_INTERVAL")
        .map(|s| s.parse::<usize>().unwrap());

    let enable_aslr = sub_m.is_present("ENABLE_ASLR");
    let asynczero = sub_m.is_present("ASYNCZERO");
    let hawkeye = sub_m
        .is_present("HAWKEYE")
        .then(|| sub_m.value_of("HAWKEYE_BLOAT_PROC").unwrap().to_owned());
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
    } else if hawkeye.is_some() {
        // Default values
        ("always".into(), "madvise".into(), 1)
    } else {
        ("always".into(), "always".into(), 1)
    };
    let (
        transparent_hugepage_khugepaged_alloc_sleep_ms,
        transparent_hugepage_khugepaged_scan_sleep_ms,
    ) = if hawkeye.is_some() {
        (60000, 10000)
    } else {
        (1000, 1000)
    };
    let mm_econ = sub_m.is_present("MM_ECON");
    let fragmentation = sub_m
        .value_of("FRAGMENTATION")
        .map(|s| s.parse::<usize>().unwrap());

    let eager = sub_m
        .values_of("EAGER")
        .map(|vs| vs.map(str::to_owned).collect());
    let transparent_hugepage_huge_addr = parse_thp_huge_addr_cli(sub_m)?;
    let mm_econ_benefits = sub_m
        .values_of("MM_ECON_BENEFIT_PER_PROC")
        .map(|s| {
            let all = s.collect::<Vec<_>>();
            all.chunks_exact(2)
                .map(|parts| (parts[0].to_owned(), parts[1].to_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(Vec::new);

    let ushell = SshShell::with_default_key(login.username, login.host)?;
    let local_git_hash = crate::local_research_workspace_git_hash()?;
    let remote_git_hash = crate::research_workspace_git_hash(&ushell)?;
    let remote_research_settings = crate::get_remote_research_settings(&ushell)?;

    let cfg = Config {
        exp: (12, "bare_metal".into()),

        workload,

        mmstats,
        meminfo_periodic,
        pftrace,

        instrumented_process,
        mmu_overhead,
        perf_counters,
        smaps_periodic,
        mmap_tracker,
        badger_trap,
        kbadgerd,
        kbadgerd_sleep_interval,

        mm_econ,
        enable_aslr,
        asynczero,
        hawkeye,
        fragmentation,

        transparent_hugepage_enabled,
        transparent_hugepage_defrag,
        transparent_hugepage_khugepaged_defrag,
        transparent_hugepage_khugepaged_alloc_sleep_ms,
        transparent_hugepage_khugepaged_scan_sleep_ms,

        eager,
        transparent_hugepage_huge_addr,
        mm_econ_benefits,

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

    let crate::exp00010::InitialSetupState {
        ref user_home,
        ref zerosim_exp_path,
        ref results_dir,
        ref time_file,
        ref sim_file,
        ref mmstats_file,
        ref badger_trap_file,
        ref pftrace_file,
        ref pftrace_rejected_file,
        ref runtime_file,
        ref bmks_dir,

        instrumented_proc,
        mmap_filter_csv_files,
        mmu_overhead,

        mut tctx,
        bgctx,
        kbadgerd_thread: _kbadgerd_thread,

        cores: _,
        damon_path: _,
        pin_path: _,
        damon_output_path: _,
        trace_file: _,
        ycsb_result_file: _,
        output_file: _,
    } = crate::exp00010::initial_setup(
        &ushell,
        cfg,
        cfg.asynczero,
        cfg.hawkeye.is_some(),
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
        cfg.badger_trap,
        cfg.mm_econ,
        cfg.pftrace,
        cfg.kbadgerd,
        cfg.kbadgerd_sleep_interval,
        cfg.eager.is_some(),
        cfg.fragmentation,
        // Run normal thp init...
        |_shell| Ok(true),
        // Compute mmap_filters_csv_files
        |results_dir| {
            cfg.mm_econ_benefits
                .clone()
                .into_iter()
                .map(|(proc_name, _)| {
                    let file = dir!(
                        results_dir,
                        cfg.gen_file_name(&format!("{}.mmap-filters.csv", &proc_name))
                    );
                    (proc_name, file)
                })
                .collect::<HashMap<_, _>>()
        },
        // Compute mmu_overhead
        |shell, mmu_overhead_file| {
            Ok(if cfg.mmu_overhead {
                let (load_misses, store_misses) = {
                    let suffix = crate::cpu::page_walk_perf_counter_suffix(shell)?;
                    (
                        format!("dtlb_load_misses.{}", suffix),
                        format!("dtlb_store_misses.{}", suffix),
                    )
                };
                let perf_counters: Vec<String> = cfg.perf_counters.clone().unwrap_or_else(|| {
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
                });

                Some((mmu_overhead_file.to_owned(), perf_counters))
            } else {
                None
            })
        },
        // Compute instrumented process
        || cfg.instrumented_process.clone(),
        // Set THP huge_addr
        |shell, _instrumented_proc| {
            if let Some((huge_addr, process)) = cfg.transparent_hugepage_huge_addr.clone() {
                turn_on_huge_addr(shell, huge_addr, process)?;
            }

            Ok(())
        },
        // Save all benefit files with the other output for the workload.
        |shell, mmap_filter_csv_files| {
            for (proc_name, filename) in cfg.mm_econ_benefits.iter() {
                println!(
                    "Reading mm_econ benefit file for process {}: {}",
                    proc_name, filename
                );
                let filter_csv_contents = fs::read_to_string(filename)?;
                let filter_csv_fname = mmap_filter_csv_files.get(proc_name).unwrap();

                // Be sure to save the contents of the mmap_filter in the results
                // so we can reference them later
                shell.run(cmd!(
                    "echo -n '{}' > {}",
                    filter_csv_contents,
                    filter_csv_fname
                ))?;
            }

            Ok(())
        },
        // No kbadgerd exceptionss...
        false,
        |_| cfg.eager.clone().unwrap(),
    )?;

    // Collect timers on VM
    let mut timers = vec![];

    // Run the workload.
    match cfg.workload {
        Workload::Mix { size } => {
            let freq = get_cpu_freq(&ushell)?;
            let metis_path = dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_METIS_SUBMODULE);
            let memhog_path = dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_MEMHOG_SUBMODULE);
            let nullfs_path = dir!(user_home, RESEARCH_WORKSPACE_PATH, ZEROSIM_NULLFS_SUBMODULE);
            let redis_conf_path = dir!(user_home, RESEARCH_WORKSPACE_PATH, REDIS_CONF);
            let mut wk = MixWorkload::new(
                zerosim_exp_path,
                &metis_path,
                &memhog_path,
                &nullfs_path,
                &redis_conf_path,
                freq,
                size,
                &mut tctx,
                &runtime_file,
            );

            // Add prefix to measure mmu overhead.
            if let Some((mmu_overhead_file, counters)) = mmu_overhead {
                let key = MixWorkloadKey::from_name(instrumented_proc.as_ref().unwrap());
                let prefix = gen_perf_command_prefix(mmu_overhead_file, &counters, "");
                wk.add_command_prefix(key, &prefix);
            }

            // Set mmap filters.
            let filters = mmap_filter_csv_files
                .into_iter()
                .map(|(p, f)| (MixWorkloadKey::from_name(p), f))
                .collect();
            wk.set_mmap_filters(&dir!(bmks_dir, "cb_wrapper"), filters);

            let _handle = time!(
                timers,
                "Start server",
                wk.start_background_processes(&ushell)?
            );

            time!(timers, "Workload", wk.run_sync(&ushell)?);
        }

        Workload::CloudsuiteWebServing { load_scale } => {
            let mut wk = CloudsuiteWebServingWorkload::new(
                load_scale,
                /* use_hhvm; keep it simple for now */ false,
                &runtime_file,
            );

            let _handles = time!(
                timers,
                "Start servers",
                wk.start_background_processes(&ushell)?
            );

            // Set mmap filters.
            let filters = mmap_filter_csv_files
                .into_iter()
                .map(|(p, f)| (CloudsuiteWebServingWorkloadKey::from_name(p), f))
                .collect();
            wk.set_mmap_filters(&ushell, filters)?;

            // Attach perf to measure mmu overhead. See the comments on `attach_perf_stat` for more
            // info about why we do it this way.
            //
            // NOTE: This should happen as close as possible to `run_sync`...
            let _perf_handle = if let Some((mmu_overhead_file, counters)) = mmu_overhead {
                let key =
                    CloudsuiteWebServingWorkloadKey::from_name(instrumented_proc.as_ref().unwrap());
                Some(wk.attach_perf_stat(&ushell, key, &mmu_overhead_file, &counters)?)
            } else {
                None
            };

            time!(timers, "Workload", wk.run_sync(&ushell)?);
        }
    }

    crate::exp00010::teardown(
        &ushell,
        &mut timers,
        bgctx,
        instrumented_proc.as_ref().map(String::as_str),
        cfg.pftrace,
        cfg.mm_econ,
        cfg.mmstats,
        cfg.meminfo_periodic,
        cfg.smaps_periodic,
        false,
        cfg.badger_trap,
        cfg.kbadgerd,
        results_dir,
        pftrace_rejected_file,
        pftrace_file,
        mmstats_file,
        badger_trap_file,
        time_file,
        sim_file,
        false,
    )?;

    let glob = cfg.gen_file_name("");
    println!(
        "RESULTS: {}",
        dir!(setup00000::HOSTNAME_SHARED_RESULTS_DIR, glob)
    );

    Ok(())
}
