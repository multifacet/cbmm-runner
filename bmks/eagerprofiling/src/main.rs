//! A utility for reading `/proc/[pid]/pagemap` to produce a profile for eager paging.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;

use eagerprofiling::{PageMap, VirtualMemoryRegion, PAGE_SIZE, VSYSCALL_SECTION_START};

const USAGE: &str = "USAGE: ./x <pid> <interval>";

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let pid = args.next().expect(USAGE);
    let interval = args.next().expect(USAGE).parse().expect(USAGE);
    println!("hello");

    let pagemap_filename = format!("/proc/{}/pagemap", pid);
    let maps_filename = format!("/proc/{}/maps", pid);

    let stop_path = std::path::PathBuf::from("/tmp/stop-readpagemap");

    let mut touched_pages = BTreeMap::new();

    while !stop_path.is_file() {
        match do_work(&pagemap_filename, &maps_filename, &mut touched_pages) {
            Err(error) => {
                // If the file is not found,
                if error.kind() == io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(error)
                }
            },
            _ => Ok(()),
        }?;

        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
    println!("world");

    let mut start = 0;
    let mut end = 0;
    const PAGE_SIZE: u64 = 0x1000;
    for addr in touched_pages.into_keys() {
        if start == 0 {
            start = addr;
            end = addr;
            continue;
        }

        // If this addr is the next page after end, update end.
        // Otherwise print the old range and start a new one
        if addr == end + PAGE_SIZE {
            end = addr
        } else {
            // If the range is only one page long, just print it alone
            if start == end {
                println!("{:X}", start);
            } else {
                println!("{:X} - {:X}", start, end);
            }

            start = addr;
            end = addr;
        }
    }

    // Print the last range
    if start == end {
        println!("{:X}", start);
    } else {
        println!("{:X} - {:X}", start, end);
    }

    Ok(())
}

fn do_work(
    pagemap_filename: &str,
    maps_filename: &str,
    touched: &mut BTreeMap<u64, ()>,
) -> io::Result<()> {
    let mut pagemap = PageMap::new(fs::File::open(pagemap_filename)?);

    let mut total_pages = 0;
    let mut untouched = 0;

    for region in fs::read_to_string(maps_filename)?
        .split_terminator('\n')
        .map(VirtualMemoryRegion::from_line)
    {
        for addr in (region.start_address..region.end_address).step_by(PAGE_SIZE) {
            if addr >= VSYSCALL_SECTION_START {
                break;
            }

            let page_info = pagemap.get_by_vaddr(addr)?;

            // Page is allocated in virtual memory but has never been touched.
            if !page_info.present() && !page_info.swap() {
                untouched += 1;
            } else {
                touched.insert(addr, ());
            }

            total_pages += 1;
        }
    }

    println!(
        "Total: {} Untouched: {} ({:0.0}%)",
        total_pages,
        untouched,
        (untouched as f64) / total_pages as f64 * 100.
    );

    Ok(())
}
