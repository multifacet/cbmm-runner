//! Utilities for setting up and running hadoop and spark.

use std::path::Path;

use spurs::{cmd, Execute, SshShell};

const APACHE_HADOOP_MIRROR: &str = "http://apache-mirror.8birdsvideo.com/";

const HADOOP_TARBALL_URL_TEMPLATE: &str = "hadoop/common/hadoop-VERSION/hadoop-VERSION.tar.gz";
const SPARK_TARBALL_URL_TEMPLATE: &str = "spark/spark-VERSION/spark-VERSION-bin-hadoop2.7.tgz";

const HADOOP_VERSION: &str = "3.1.3";
const SPARK_VERSION: &str = "2.4.4";

/// Download and untar the hadoop tarball for the given version as `path/hadoop/`, deleting
/// anything that was previously there.
pub fn download_hadoop_tarball<P>(ushell: &SshShell, path: &P) -> Result<(), failure::Error>
where
    P: AsRef<Path>,
{
    let url = APACHE_HADOOP_MIRROR.to_owned()
        + &HADOOP_TARBALL_URL_TEMPLATE.replace("VERSION", HADOOP_VERSION);

    with_shell! { ushell =>
        cmd!("wget -O /tmp/hadoop.tgz {}", url),
        cmd!("tar xvzf /tmp/hadoop.tgz"),
        cmd!("rm -rf {}/hadoop", path.as_ref().display()),
        cmd!("mv hadoop-{} {}/hadoop", HADOOP_VERSION, path.as_ref().display()),
    }

    Ok(())
}

/// Download and untar the spark tarball for the given version as `$HOME/hadoop/`.
pub fn download_spark_tarball<P>(ushell: &SshShell, path: &P) -> Result<(), failure::Error>
where
    P: AsRef<Path>,
{
    let url = APACHE_HADOOP_MIRROR.to_owned()
        + &SPARK_TARBALL_URL_TEMPLATE.replace("VERSION", SPARK_VERSION);

    with_shell! { ushell =>
        cmd!("wget -O /tmp/spark.tgz {}", url),
        cmd!("tar xvzf /tmp/spark.tgz"),
        cmd!("rm -rf {}/spark", path.as_ref().display()),
        cmd!("mv spark-{}-bin-hadoop2.7 {}/spark", SPARK_VERSION, path.as_ref().display()),
    }

    Ok(())
}

/// Start Spark master and worker on the given machine. The shell should not be a root shell.
pub fn start_spark<P: AsRef<Path>>(shell: &SshShell, spark_home: &P) -> Result<(), failure::Error> {
    shell.run(cmd!(
        "bash -x {}/sbin/start-master.sh -h localhost -p 7077",
        spark_home.as_ref().display()
    ))?;

    shell.run(cmd!(
        "bash -x {}/sbin/start-slave.sh localhost:7077",
        spark_home.as_ref().display()
    ))?;

    Ok(())
}

/// Stop spark running on this machine.
pub fn stop_spark<P: AsRef<Path>>(shell: &SshShell, spark_home: &P) -> Result<(), failure::Error> {
    shell.run(cmd!(
        "bash -x {}/sbin/stop-all.sh",
        spark_home.as_ref().display()
    ))?;

    Ok(())
}
