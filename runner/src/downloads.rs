//! Utilities for downloading stuff.
//!
//! NOTE: for utilities for Hadoop/Spark see `crate::hadoop`, as they are especially
//! painful.

use spurs::{cmd, Execute, SshShell};

/// A list of avaiable artifacts. See `artifact_info` for more info on the exact versions and URLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Artifact {
    Vagrant,
    Qemu,
    Maven,
    /// Intel PIN
    Pin,
    /// KyotoCabinet core library.
    KyotoCabinetCore,
    /// KyotoCabinet java client library.
    KyotoCabinetJava,
    /// The linux kernel.
    Linux,
    /// PARSEC benchmark suit
    Parsec,
}

/// Represents a possible artifact that can be downloaded.
#[derive(Debug, Clone)]
pub struct Download<'s> {
    /// The URL of the artifact, from which it can be downloaded.
    pub url: &'s str,
    /// The name of the downloaded artifact.
    pub name: &'s str,
    /// The version string of the artifact.
    pub version: &'s str,
}

/// Get the info for the given artifact.
pub fn artifact_info(artifact: Artifact) -> Download<'static> {
    use Artifact::*;

    match artifact {
        Vagrant => Download {
            url: "https://releases.hashicorp.com/vagrant/2.2.14/vagrant_2.2.14_x86_64.rpm",
            name: "vagrant_2.2.14_x86_64.rpm",
            version: "2.2.14",
        },
        Qemu => Download {
            url: "https://download.qemu.org/qemu-4.0.0.tar.xz",
            name: "qemu-4.0.0.tar.xz",
            version: "4.0.0",
        },
        Maven => Download {
            url: "https://downloads.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz",
            name: "apache-maven-3.6.3-bin.tar.gz",
            version: "3.6.3",
        },
        Pin => Download {
            url: "https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz",
            name: "pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz",
            version: "3.11-97998-g7ecce2dac",
        },
        KyotoCabinetCore => Download {
            url: "https://fallabs.com/kyotocabinet/pkg/kyotocabinet-1.2.77.tar.gz",
            name: "kyotocabinet-1.2.77.tar.gz",
            version: "1.2.77",
        },
        KyotoCabinetJava => Download {
            url: "https://fallabs.com/kyotocabinet/javapkg/kyotocabinet-java-1.24.tar.gz",
            name:"kyotocabinet-java-1.24.tar.gz",
            version: "1.24",
        },
        Linux => Download {
            url: "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.5.tar.xz",
            name: "linux-5.5.tar.xz",
            version: "5.5",
        },
        Parsec => Download {
            url: "https://parsec.cs.princeton.edu/download/3.0/parsec-3.0.tar.gz",
            name: "parsec-3.0.tar.gz",
            version: "3.0",
        },
    }
}

/// Use `shell` to download the artifact to the directory `to` only if the tarball doesn't already
/// exist. Then, rename the tarball to `name` if any name is given. Returns the `Download` with
/// artifact info, including the original name of the download.
pub fn download(
    shell: &SshShell,
    artifact: Artifact,
    to: &str,
    name: Option<&str>,
) -> Result<Download<'static>, failure::Error> {
    let info = artifact_info(artifact);

    // Some websites reject non-browsers, so pretend to be Google Chrome.
    const USER_AGENT: &str = r#"--user-agent="Mozilla/5.0 (Windows NT 10.0; WOW64) \
                                AppleWebKit/537.36 (KHTML, like Gecko) \
                                Chrome/51.0.2704.103 Safari/537.36""#;

    // Check if the file exists and then maybe download.
    if let Some(name) = name {
        shell.run(
            cmd!(
                "[ -e {} ] || wget {} -O {} {}",
                name,
                USER_AGENT,
                name,
                info.url
            )
            .cwd(to),
        )?;
    } else {
        shell.run(cmd!("[ -e {} ] || wget {} {}", info.name, USER_AGENT, info.url).cwd(to))?;
    }

    Ok(info)
}

/// Use `shell` to download the artifact to the directory `to` only if the tarball doesn't already
/// exist. Then, extract the artifact to a directory with the given `name`; if no name is given,
/// then the default name is used. Returns the `Download` with artifact info.
pub fn download_and_extract(
    shell: &SshShell,
    artifact: Artifact,
    to: &str,
    name: Option<&str>,
) -> Result<Download<'static>, failure::Error> {
    // Download, keep the original name.
    let info = download(shell, artifact, to, None)?;

    // Now extract.
    if let Some(name) = name {
        shell.run(cmd!("mkdir -p {}", name).cwd(to))?;
        shell.run(cmd!("tar -C {} --strip-components=1 -xvf {}", name, info.name).cwd(to))?;
    } else {
        shell.run(cmd!("tar -xvf {}", info.name).cwd(to))?;
    }

    Ok(info)
}
