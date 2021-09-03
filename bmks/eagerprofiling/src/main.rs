//! A utility for reading `/proc/[pid]/pagemap` to produce a profile for eager paging.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;

use eagerprofiling::{PageMap, VirtualMemoryRegion, PAGE_SIZE, VSYSCALL_SECTION_START};

const USAGE: &str = "USAGE: ./x <pid> <interval>";

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let pid = args.next().expect(USAGE);
    let interval = args.next().expect(USAGE).parse().expect(USAGE);

    let pagemap_filename = format!("/proc/{}/pagemap", pid);
    let maps_filename = format!("/proc/{}/maps", pid);

    let stop_path = std::path::PathBuf::from("/tmp/stop-readpagemap");

    let mut touched_pages = HashSet::new();

    while !stop_path.is_file() {
        match do_work(&pagemap_filename, &maps_filename, &mut touched_pages) {
            Err(error) => {
                if error.kind() == io::ErrorKind::NotFound {
                    break;
                } else {
                    Err(error)
                }
            },
            _ => Ok(()),
        }?;

        std::thread::sleep(std::time::Duration::from_secs(interval));
    }

    for addr in touched_pages.into_iter() {
        println!("{:X}", addr);
    }

    Ok(())
}

fn do_work(
    pagemap_filename: &str,
    maps_filename: &str,
    touched: &mut HashSet<u64>,
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
                touched.insert(addr);
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
