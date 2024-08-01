use lazy_static::lazy_static;
use pagemap::{page_size, PageMap, PageMapEntry};
use std::{collections::HashMap, env, fmt, fs, process};

/* FIXME: Make this work for different granules */
const CONT_PTES: u64 = 16;
const CONT_PMDS: u64 = 16;

/* PM_THP -> THP/PMD-mapped pagemap entry (!= KPF_THP which is a THP compound struct page) */
const PM_THP: u64 = 59;
/* PM_CONT -> CONT mapped PTE / PMD */
const PM_CONT: u64 = 60;

const SYSFS_HPMD_SIZE: &'static str = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size";

lazy_static! {
    static ref PTE_SIZE: u64 = page_size().unwrap();
    static ref PMD_SIZE: u64 = fs::read_to_string(SYSFS_HPMD_SIZE)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    static ref PTE_SHIFT: u32 = PTE_SIZE.trailing_zeros();
    static ref PMD_SHIFT: u32 = PMD_SIZE.trailing_zeros();
    static ref VERBOSE: bool = env::var("PGC_VERBOSE").is_ok();
    static ref DUMPVPN: bool = env::var("PGC_DUMPVPN").is_ok();
}

// Human-readable size conversion
const SUFFIXES: [&str; 8] = ["", "K", "M", "G", "T", "P", "E", "Z"];
fn size_to_str(sz: u64) -> String {
    let mut v = sz;
    let mut idx = 0;

    while v >> 10 > 0 {
        idx += 1;
        v >>= 10;
    }

    format!("{}{}B", v, SUFFIXES[idx])
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
enum EntryType {
    Anon,
    File,
}

impl fmt::Display for EntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = match self {
            EntryType::Anon => "Anon",
            EntryType::File => "File",
        };
        write!(f, "{}", val)
    }
}

impl EntryType {
    fn from_pagemap(entry: PageMapEntry) -> Self {
        if entry.file_mapped() {
            Self::File
        } else {
            Self::Anon
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
enum EntrySize {
    Pte,
    Pmd,
}

impl EntrySize {
    fn size(&self) -> u64 {
        match self {
            EntrySize::Pte => *PTE_SIZE,
            EntrySize::Pmd => *PMD_SIZE,
        }
    }

    fn contsize(&self) -> u64 {
        match self {
            EntrySize::Pte => CONT_PTES,
            EntrySize::Pmd => CONT_PMDS,
        }
    }

    fn contmask(&self) -> u64 {
        match self {
            EntrySize::Pte => CONT_PTES - 1,
            EntrySize::Pmd => (CONT_PMDS << (*PMD_SHIFT - *PTE_SHIFT)) - 1,
        }
    }

    fn contshift(&self) -> u32 {
        match self {
            EntrySize::Pte => 0,
            EntrySize::Pmd => *PMD_SHIFT - *PTE_SHIFT,
        }
    }

    fn align(addr: u64, size: u64) -> u64 {
        (addr + size) & !(size - 1)
    }

    fn next(&self, addr: u64) -> u64 {
        Self::align(addr, self.size() * self.contsize())
    }

    fn offset(&self, addr: u64) -> u64 {
        (addr & self.contmask()) >> self.contshift()
    }

    fn from_pagemap(entry: PageMapEntry) -> Self {
        if entry.raw_pagemap() >> PM_THP & 1 == 0 {
            Self::Pte
        } else {
            Self::Pmd
        }
    }

    fn from_kflags(entry: PageMapEntry) -> Self {
        if entry.thp().unwrap_or(false) {
            Self::Pmd
        } else {
            Self::Pte
        }
    }
}

impl fmt::Display for EntrySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = match self {
            EntrySize::Pte => "PTE",
            EntrySize::Pmd => "PMD",
        };
        write!(f, "{}", val)
    }
}

#[derive(Clone, Copy, Debug)]
struct Counter {
    entry_type: EntryType,
    entry_size: EntrySize,

    total_entries: u64,
    aligned_entries: u64,
    cont_entries: u64,
}

impl Counter {
    fn new(entry_type: EntryType, entry_size: EntrySize) -> Self {
        Self {
            entry_type,
            entry_size,
            total_entries: 0,
            aligned_entries: 0,
            cont_entries: 0,
        }
    }

    fn cont_size(&self) -> u64 {
        self.cont_entries * self.entry_size.contsize() * self.entry_size.size()
    }

    fn aligned_size(&self) -> u64 {
        self.aligned_entries * self.entry_size.contsize() * self.entry_size.size()
    }

    fn total_size(&self) -> u64 {
        self.total_entries * self.entry_size.size()
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cont_size = self.cont_size();
        let aligned_size = self.aligned_size();
        let total_size = self.total_size();

        write!(
            f,
            "{} {}, Total: {} ({}), Aligned: {} ({}), Cont: {} ({}), Coverage: {:.2}%, Potential Coverage: {:.2}%",
            self.entry_type,
            self.entry_size,
            self.total_entries,
            size_to_str(total_size),
            self.aligned_entries,
            size_to_str(aligned_size),
            self.cont_entries,
            size_to_str(cont_size),
            ((self.cont_entries * self.entry_size.contsize()) as f64 / self.total_entries as f64) * 100.0,
            ((self.aligned_entries * self.entry_size.contsize()) as f64 / self.total_entries as f64) * 100.0,
        )
    }
}

fn print_stats(entry_type: EntryType, counters: &HashMap<(EntryType, EntrySize), Counter>) {
    let ptes = counters[&(entry_type, EntrySize::Pte)];
    let pmds = counters[&(entry_type, EntrySize::Pmd)];

    if *VERBOSE {
        println!("{:?}", ptes);
        println!("{:?}", pmds);
    }
    println!("{}", ptes);
    println!("{}", pmds);

    println!(
        "Total {} coverage: {:.2}%, PTE: {:.2}%, THP: {:.2}%\n",
        entry_type,
        ((ptes.cont_entries * EntrySize::Pte.contsize()
            + EntrySize::Pmd.contsize() * pmds.cont_entries * 512) as f64
            / (ptes.total_entries + pmds.total_entries * 512) as f64)
            * 100.0,
        ((EntrySize::Pte.contsize() * ptes.cont_entries) as f64
            / (ptes.total_entries + pmds.total_entries * 512) as f64)
            * 100.0,
        ((EntrySize::Pmd.contsize() * pmds.cont_entries * 512) as f64
            / (ptes.total_entries + pmds.total_entries * 512) as f64)
            * 100.0
    );

    println!(
        "{} 4K: {} ({}), 64K: {} ({}), 2M: {} ({}), 32M: {} ({})",
        entry_type,
        ptes.total_entries - ptes.cont_entries * EntrySize::Pte.contsize(),
        size_to_str(ptes.total_size() - ptes.cont_size()),
        ptes.cont_entries,
        size_to_str(ptes.cont_size()),
        pmds.total_entries - pmds.cont_entries * EntrySize::Pmd.contsize(),
        size_to_str(pmds.total_size() - pmds.cont_size()),
        pmds.cont_entries,
        size_to_str(pmds.cont_size())
    );

    println!("");
}

fn main() {
    /* usage: ./pagecollect [pid] */
    let pid = env::args()
        .nth(1)
        .map_or_else(|| process::id() as u64, |v| v.parse().unwrap());

    let mut counters: HashMap<(EntryType, EntrySize), Counter> = HashMap::from([
        (
            (EntryType::Anon, EntrySize::Pte),
            Counter::new(EntryType::Anon, EntrySize::Pte),
        ),
        (
            (EntryType::Anon, EntrySize::Pmd),
            Counter::new(EntryType::Anon, EntrySize::Pmd),
        ),
        (
            (EntryType::File, EntrySize::Pte),
            Counter::new(EntryType::File, EntrySize::Pte),
        ),
        (
            (EntryType::File, EntrySize::Pmd),
            Counter::new(EntryType::File, EntrySize::Pmd),
        ),
    ]);

    let mut pagemap = PageMap::new(pid).unwrap();
    for mapping in pagemap.maps().unwrap().iter() {
        if *VERBOSE || *DUMPVPN {
            println!("-> {}", mapping);
        }

        let vma = mapping.vma();
        let start = vma.start_address();
        let end = vma.last_address();

        /*
         * PFN of the first (potential) range entry. We use it to check for aligned
         * (but not necessarily CONT-mapped ranges
         */
        let mut anchor_pfn = None;
        let mut anchor_size = None;

        /*
         * Set if the first / anchor entry has the CONT bit set. It should be set
         * for all or none of the range entries.
         */
        let mut inside_range = false;
        let mut mismatch = false;

        let mut addr = start;
        while addr <= end {
            let vpn = addr >> *PTE_SHIFT;
            let entry = pagemap.pagemap_vpn(vpn).unwrap();
            let mut entry_size = EntrySize::from_pagemap(entry);

            if !entry.present() {
                /* Invalid range with non-present members */
                //assert!(inside_range == false);

                if *VERBOSE {
                    println!("\t- VPN: 0x{:x} not present", vpn);
                }

                addr = entry_size.next(addr);
                continue;
            }

            if entry_size == EntrySize::Pte {
                entry_size = EntrySize::from_kflags(entry);
            }

            if !entry.anon().unwrap_or(false) && !entry.mmap().unwrap_or(false) {
                /* Invalid range for non-anon/file entires */
                //assert!(inside_range == false);

                if *VERBOSE {
                    println!("\t- VPN: 0x{:x} not anon/mmap", vpn);
                }

                addr = entry_size.next(addr);
            }

            let pfn = entry.pfn().unwrap();
            let cont = entry.raw_pagemap() >> PM_CONT & 1 == 1;

            let vpn_offset = entry_size.offset(vpn);
            let pfn_offset = entry_size.offset(pfn);

            if *VERBOSE || *DUMPVPN {
                println!(
                    "\t- VPN: 0x{:x}(+{}), PFN: 0x{:x}(+{}), {}{}{}{}",
                    vpn,
                    vpn_offset,
                    pfn,
                    pfn_offset,
                    entry_size,
                    if cont { ", Cont" } else { "" },
                    if vpn_offset == pfn_offset {
                        ", Aligned"
                    } else {
                        ""
                    },
                    if vpn_offset != 0
                        && pfn - (pfn_offset << entry_size.contshift()) != anchor_pfn.unwrap_or(0)
                    {
                        ", Mismatch"
                    } else {
                        ""
                    },
                )
            }

            counters
                .entry((EntryType::from_pagemap(entry), entry_size))
                .and_modify(|counter| counter.total_entries += 1);


            if inside_range {
                /* Make sure inside_range can only be set by the first entry */
                //assert!(vpn_offset != 0);
                /* Invalid range with mixed sizes */
                //assert!(entry_size == anchor_size.unwrap());
            }

            /* VPN-PFN offset mismatch */
            if vpn_offset != pfn_offset {
                /* Invalid range, CONT bit set while the offsets don't match */
                //assert!(inside_range == false);

                /* Don't skip the rest of the range, make sure the rest of the entries are valid */
                mismatch = true;
                addr += entry_size.size();
                continue;
            }

            /* Start of a potential range */
            if vpn_offset == 0 {
                /* The last entry of the previous range should have reset this */
                //assert!(inside_range == false);

                /* Set the anchor */
                anchor_pfn = Some(pfn);
                anchor_size = Some(entry_size);

                /* If it's CONT-mapped, make sure the rest of the entries are also CONT mapped */
                inside_range = cont;

                mismatch = false;
                addr += entry_size.size();
                continue;
            }

            /* Invalid range, mismatch between anchor and the rest wrt CONT bit*/
            //assert!(inside_range == cont);

            /* PFN-APFN offset mismatch */
            if pfn - (pfn_offset << entry_size.contshift()) != anchor_pfn.unwrap_or(0) {
                /* Invalid range, PFN offset doesn't match */
                //assert!(cont == false);

                mismatch = true;
                addr += entry_size.size();
                continue;
            }

            /* Reached the end of the range, update the counters */
            if vpn_offset == entry_size.contsize() - 1 {
                /* Reset the anchor */
                anchor_pfn = None;
                anchor_size = None;

                /* Reset inside_range */
                inside_range = false;

                if !mismatch {
                    counters
                        .entry((EntryType::from_pagemap(entry), entry_size))
                        .and_modify(|counter| counter.aligned_entries += 1);
                }
                mismatch = false;

                if cont == true {
                    counters
                        .entry((EntryType::from_pagemap(entry), entry_size))
                        .and_modify(|counter| counter.cont_entries += 1);
                }
            }
            addr += entry_size.size();
        }
    }

    println!("");

    print_stats(EntryType::Anon, &counters);
    print_stats(EntryType::File, &counters);
}
