//! Some routines for adding common CLI options in a consistent, less boilerplatey way.

/// CLI options for compiling kernels.
pub mod setup_kernel {
    use clap::{App, Arg, ArgGroup, ArgMatches};

    use crate::GitRepo;

    pub fn add_cli_options<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.arg(
            Arg::with_name("COMMITISH")
                .required(true)
                .takes_value(true)
                .help("The git branch/hash/tag to compile the kernel from (e.g. master or v4.10)"),
        )
        .arg(
            Arg::with_name("SECRET")
                .long("secret")
                .takes_value(true)
                .requires("HTTPS")
                .requires("GIT_USERNAME")
                .help("A secret token for accessing a private repository"),
        )
        .arg(
            Arg::with_name("HTTPS")
                .long("https")
                .takes_value(true)
                .help("The git repository to compile the kernel from as an HTTPS URL."),
        )
        .arg(
            Arg::with_name("SSH")
                .long("ssh")
                .takes_value(true)
                .help("The git repository to compile the kernel from as an SSH address."),
        )
        .group(
            ArgGroup::with_name("GIT_REPO")
                .arg("HTTPS")
                .arg("SSH")
                .required(true),
        )
        .arg(
            Arg::with_name("GIT_USERNAME")
                .long("username")
                .takes_value(true)
                .requires("HTTPS")
                .requires("SECRET")
                .help("A username for accessing a private repository"),
        )
        .arg(
            Arg::with_name("CONFIGS")
                .multiple(true)
                .allow_hyphen_values(true)
                .validator(validate_config_option)
                .help(
                    "Space separated list of Linux kernel configuration options, prefixed by \
                     + to enable and - to disable. For example, +CONFIG_ZSWAP or \
                     -CONFIG_PAGE_TABLE_ISOLATION",
                ),
        )
    }

    /// Parse and return the values added by `add_kernel_cli_options`.
    pub fn parse_cli_options<'a>(
        sub_m: &'a ArgMatches<'a>,
    ) -> (String, &'a str, Vec<(&'a str, bool)>, Option<&'a str>) {
        let secret = sub_m.value_of("SECRET");
        let git_repo = {
            let https = sub_m.value_of("HTTPS");
            let ssh = sub_m.value_of("SSH");
            let username = sub_m.value_of("GIT_USERNAME");

            match (https, ssh, secret) {
                (Some(https), None, None) => GitRepo::HttpsPublic { repo: https },
                (Some(https), None, Some(_)) => GitRepo::HttpsPrivate {
                    repo: https,
                    username: username.unwrap(),
                },
                (None, Some(ssh), None) => GitRepo::Ssh { repo: ssh },
                _ => unreachable!(),
            }
        }
        .git_repo_access_url(secret);
        let commitish = sub_m.value_of("COMMITISH").unwrap();
        let kernel_config: Vec<_> = sub_m
            .values_of("CONFIGS")
            .map(|values| {
                values
                    .map(|arg| parse_config_option(arg).unwrap())
                    .collect()
            })
            .unwrap_or_else(|| vec![]);

        (git_repo, commitish, kernel_config, secret)
    }

    fn validate_config_option(opt: String) -> Result<(), String> {
        parse_config_option(&opt)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn parse_config_option(opt: &str) -> Result<(&str, bool), failure::Error> {
        fn check(s: &str) -> Result<&str, failure::Error> {
            if s.is_empty() {
                Err(failure::format_err!("Empty string is not a valid option"))
            } else {
                for c in s.chars() {
                    if !c.is_ascii_alphanumeric() && c != '_' {
                        return Err(failure::format_err!("Invalid config name \"{}\"", s));
                    }
                }
                Ok(s)
            }
        }

        if opt.is_empty() {
            Err(failure::format_err!("Empty string is not a valid option"))
        } else {
            match &opt[0..1] {
                "+" => Ok((check(&opt[1..])?, true)),
                "-" => Ok((check(&opt[1..])?, false)),
                _ => Err(failure::format_err!(
                    "Kernel config option must be prefixed with + or -"
                )),
            }
        }
    }
}
