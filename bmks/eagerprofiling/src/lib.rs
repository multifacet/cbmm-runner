//! A utility for reading `/proc/[pid]/pagemap` to produce a profile for eager paging.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;

pub const VSYSCALL_SECTION_START: u64 = 0xffffffffff600000;

// A bunch of constants from Linux 4.15 (probably valid on other versions)...
pub const PAGEMAP_PRESENT_MASK: u64 = 1 << 63;
pub const PAGEMAP_SWAP_MASK: u64 = 1 << 62;
pub const PAGEMAP_FILE_MASK: u64 = 1 << 61;
pub const PAGEMAP_EXCLUSIVE_MASK: u64 = 1 << 56;
pub const PAGEMAP_SOFT_DIRTY_MASK: u64 = 1 << 55;
pub const PAGEMAP_PFN_MASK: u64 = (1 << 55) - 1; // bits 54:0

/// The data for a single page of virtual memory in `/proc/[pid]/pagemap`. That file is basically a
/// huge array of these values.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct SinglePageData(u64);

impl SinglePageData {
    /// Is the page present in RAM?
    pub fn present(self) -> bool {
        self.0 & PAGEMAP_PRESENT_MASK != 0
    }

    /// Is the page swapped out?
    pub fn swap(self) -> bool {
        self.0 & PAGEMAP_SWAP_MASK != 0
    }

    /// Is the page file-backed/shared-anonymous?
    pub fn file_backed(self) -> bool {
        self.0 & PAGEMAP_FILE_MASK != 0
    }

    /// Is the page mapped exclusively (i.e., by exactly one user)?
    pub fn exclusive(self) -> bool {
        self.0 & PAGEMAP_EXCLUSIVE_MASK != 0
    }

    /// Can be used to manually implement dirty bits in software (separately from the
    /// hardware-based implementation).
    pub fn soft_dirty(self) -> bool {
        self.0 & PAGEMAP_SOFT_DIRTY_MASK != 0
    }

    /// The page frame number of the physical page backing this virtual page if the page is present
    /// in RAM. Otherwise, if the page is swapped out, then bits 4-0 indicate swap type (i.e.,
    /// which swap space), and bits 54-5 indicate the swap slot on the swap space.
    pub fn pfn(self) -> u64 {
        self.0 & PAGEMAP_PFN_MASK
    }
}

/// The contents of `/proc/[pid]/pagemap` in a seekable way.
pub struct PageMap {
    file: BufReader<File>,
}

impl PageMap {
    pub fn new(file: File) -> Self {
        PageMap {
            file: BufReader::new(file),
        }
    }

    /// Get the `SinglePageData` for the page starting at the given address.
    pub fn get_by_vaddr(&mut self, vaddr: u64) -> std::io::Result<SinglePageData> {
        // Sanity check
        assert!(vaddr & (PAGE_SIZE as u64 - 1) == 0);

        let offset = (vaddr >> PAGE_SHIFT) * 8;

        // Read data from file...
        let single_page = {
            let mut data = [0u8; 8];
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.read_exact(&mut data)?;

            unsafe { std::mem::transmute(data) }
        };

        Ok(single_page)
    }
}

/// A single memory region from `/proc/[pid]/maps`.
pub struct VirtualMemoryRegion {
    /// inclusive
    pub start_address: u64,
    /// exclusive
    pub end_address: u64,
    // permissions: u16,
    // offset: u64,
    // dev_major: u8,
    // dev_minor: u8,
    // inode: u64,
    // path: String,
}

impl VirtualMemoryRegion {
    /// Instantiate a `VirtualMemoryRegion` from a line of `/proc/[pid]/maps`.
    pub fn from_line(line: &str) -> Self {
        let mut parts = line.split_whitespace();

        let (start_address, end_address) = {
            let addr_str = parts.next().unwrap();
            let mut addr_parts = addr_str.split("-");
            let start_str = addr_parts.next().unwrap();
            let end_str = addr_parts.next().unwrap();

            let start = u64::from_str_radix(start_str, 16).unwrap();
            let end = u64::from_str_radix(end_str, 16).unwrap();

            (start, end)
        };

        VirtualMemoryRegion {
            start_address,
            end_address,
        }
    }
}
