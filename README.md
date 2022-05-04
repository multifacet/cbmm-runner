# CBMM benchmark `runner`

This repository contains the benchmarks and scripts for running experiments for
CBMM (ACT '22), most notably, the `runner` program and any benchmarks it
requires.

The `runner` is meant to be run on one machine (the _driver_) targetting
another machine (the _test_ machine) over SSH.

## Repository Contents

- `runner/` is a self-contained program that is capable of setting up any
  experiment for the project and running it.
    - For more info on usage:
        - `cd runner; cargo run -- help`.
        - There is a `README.md`
        - The code itself is also pretty well-documented IMHO.
- `bmks/` contains files needed for some benchmarks (e.g. NAS).

## List of `runner` Experiments

The `runner` has a bunch of subcommands (see `./runner help`) to do different
setup routines and run different experiments from our paper. Each one has a
submodule in the `runner` source code and command line option. This section
contains a list of the current set of sucommands and what each one does. Please
see the source code and the `./runner help` messages for more info.

Setup routines do setup/configuration tasks. They do not run any experiments,
but are required to run before experiments can run.

- `setup00000`: Installs a bunch of dependencies and benchmarks on the _driver_ machine.
- `setup00003`: Compiles and installs the specified kernel on the _driver_ machine.
- `setup00004`: Compiles and installs HawkEye (ASPLOS '19) on the _driver_ machine.

Experiments:

- `exp00010`: Runs one of a few single-process workloads.
  - `TimeLoop`, `LocalityMemAccess`, `TimeMmapTouch`, `ThpUbmk`, `ThpUbmkShm`:
    A collection of microbenchmarks intended to stress different architectural
    and kernel-level memory structures. 
  - `Memcached`, `MemcachedYcsb`, `Redis`, `RedisYcsb`, `MongoDB`: various
    data-stores driven by either sequential or YCSB access patterns.
  - `Graph500`: a graph processing benchmark.
  - `Spec2017Mcf`, `Spec2017Xalancbmk`, `Spec2017Xz`: Various workloads from
    SPEC 2017, with options to scale up the workload size for some workloads.
  - `Canneal`: From the PARSEC benchmark suite, also with options to scale up
    the workload.
  - `NasCG`: CG from the NAS Parallel Benchmark suite.
- `exp00012`: Runs one of a few multi-process workloads.
  - `Mix`: a mix of redis, metis (in-memory MR), and memhog.
  - `MixYcsb`: same, but redis uses YCSB.
  - `CloudsuiteWebServing`: runs the web-serving benchmark from cloudsuite.

## Licensing

The tools in this repository are licensed under the Apache v2 open-source license.
