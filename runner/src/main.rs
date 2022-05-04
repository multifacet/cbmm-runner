//! This program runs different routines remotely. Which routine is chosen by passing different
//! command line arguments. certain routines require extra arguments.

fn run() -> Result<(), failure::Error> {
    let matches = clap::App::new("runner")
        .about(
            "This program runs different routines remotely. Which routine is chosen by passing \
             different command line arguments. certain routines require extra arguments.",
        )
        .arg(
            clap::Arg::with_name("PRINT_RESULTS_PATH")
                .long("print_results_path")
                .help("(Obsolete) The results path is always printed."),
        )
        .subcommand(runner::setup00000::cli_options())
        .subcommand(runner::setup00003::cli_options())
        .subcommand(runner::setup00004::cli_options())
        .subcommand(runner::exp00010::cli_options())
        .subcommand(runner::exp00012::cli_options())
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .setting(clap::AppSettings::DisableVersion)
        .get_matches();

    match matches.subcommand() {
        ("setup00000", Some(sub_m)) => runner::setup00000::run(sub_m),
        ("setup00003", Some(sub_m)) => runner::setup00003::run(sub_m),
        ("setup00004", Some(sub_m)) => runner::setup00004::run(sub_m),

        ("exp00010", Some(sub_m)) => runner::exp00010::run(sub_m),
        ("exp00012", Some(sub_m)) => runner::exp00012::run(sub_m),

        _ => {
            unreachable!();
        }
    }
}

fn main() {
    use console::style;

    env_logger::init();

    // Set the RUST_BACKTRACE environment variable so that we always get backtraces. Normally, one
    // doesn't want this because of the performance penalty, but in this case, we don't care too
    // much, whereas the debugging improve is massive.
    std::env::set_var("RUST_BACKTRACE", "1");

    // If an error occurred, try to print something helpful.
    if let Err(err) = run() {
        const MESSAGE: &str = r#"== ERROR ==================================================================================
`runner` encountered an error. The command log above may offer clues. If the error pertains to SSH,
you may be able to get useful information by setting the RUST_LOG=debug environment variable. It is
recommended that you use `debug` builds of `runner`, rather than `release`, as the performance of
`runner` is not that important and is almost always dominated by the experiment being run.
"#;

        println!("{}", style(MESSAGE).red().bold());

        // Errors from SSH commands
        if err.downcast_ref::<spurs::SshError>().is_some() {
            println!("An error occurred while attempting to run a command over SSH");
        }

        // Print error and backtrace
        println!(
            "`runner` encountered the following error:\n{}\n{}",
            err.as_fail(),
            err.backtrace(),
        );

        std::process::exit(101);
    }
}
