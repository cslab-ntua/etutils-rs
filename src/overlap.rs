use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::{env, usize};

use strum::{EnumCount, EnumIter, FromRepr, IntoEnumIterator};

const PAGE_OFFSET: usize = 0xffff000000000000;
const PAGE_SIZE: usize = 4096;
const TLBSIZE: usize = 1280;

const USAGE: &str = "usage: ./leshy <input> <output> <target> <slack>";

const SUFFIXES: [&str; 8] = ["", "K", "M", "G", "T", "P", "E", "Z"];
fn size_to_str(sz: usize) -> String {
    let mut v = sz;
    let mut idx = 0;

    while v >> 10 > 0 {
        idx += 1;
        v >>= 10;
    }

    format!("{}{}B", v, SUFFIXES[idx])
}

fn align(n: usize, m: usize, up: bool) -> usize {
    assert!(m.is_power_of_two());
    let mut ret = n & !(m - 1);
    if up && (ret != n) {
        ret += m;
    }

    ret
}

fn is_kernel_address(address: usize) -> bool {
    address >= PAGE_OFFSET
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, EnumIter, EnumCount, FromRepr)]
enum PageSize {
    Pte = 0,
    ContPte,
    Pmd,
    ContPmd,
}

impl PageSize {
    fn order(&self) -> usize {
        match self {
            Self::Pte => 0,
            Self::ContPte => 4,
            Self::Pmd => 9,
            Self::ContPmd => 13,
        }
    }

    fn nr_pages(&self) -> usize {
        1 << self.order()
    }

    fn bytes(&self) -> usize {
        self.nr_pages() * PAGE_SIZE
    }

    fn subentries(&self) -> usize {
        match self {
            Self::Pte => 1,
            Self::ContPte => 16,
            Self::Pmd => 32,
            Self::ContPmd => 16,
        }
    }
}

enum MissTraceLine {
    Address(usize),
    Latency(usize),
}

impl TryFrom<&str> for MissTraceLine {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.strip_prefix("0x") {
            Some(address) => Ok(Self::Address(
                usize::from_str_radix(address, 16).map_err(|_| "invalid hex")?,
            )),
            None => Ok(Self::Latency(
                s.split_once(' ')
                    .ok_or("invalid lat")?
                    .0
                    .parse::<usize>()
                    .map_err(|_| "invalid lat")?,
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct TraceEntry {
    address: usize,
    is_kernel: bool,

    count: usize,
    latencies: Vec<usize>,

    is_compound: bool,
    subentries: usize,
    basepages: usize,

    size: Option<PageSize>,
}

impl TraceEntry {
    fn occupancy(&self) -> usize {
        if self.size.is_none() {
            return 100
        }

        let size = self.size.unwrap();
        match size {
            PageSize::Pte => 100,
            _ => self.subentries * 100 / size.subentries(),
        }
    }
}

impl Ord for TraceEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.count.cmp(&other.count).then_with(|| {
            self.occupancy().cmp(&other.occupancy()).then_with(|| {
                other
                    .latencies
                    .iter()
                    .sum::<usize>()
                    .cmp(&self.latencies.iter().sum::<usize>())
            })
        })
    }
}

impl fmt::Display for TraceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} address: 0x{:x}, count: {}, entries: {}, occupancy: {:.2}%, 4K pages: {}",
            match self.size {
                Some(size) => format!("{:?}", size),
                None => "address".to_string(),
            },
            self.address,
            self.count,
            self.subentries,
            self.occupancy(),
            self.basepages,
        )
    }
}

impl PartialOrd for TraceEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug)]
struct Trace {
    file: PathBuf,
    entries: Vec<TraceEntry>,
    buckets: HashMap<PageSize, Vec<TraceEntry>>,
}

impl Trace {
    fn new(file: PathBuf) -> Self {
        let mut buckets = HashMap::new();
        PageSize::iter().for_each(|pagesize| {
            buckets.insert(pagesize, vec![]);
        });

        Self {
            file,
            entries: vec![],
            buckets,
        }
    }

    fn total_count(&self) -> usize {
        self.entries.iter().map(|x| x.count).sum()
    }

    fn count_by_type(&self, kernel: bool) -> usize {
        self.entries
            .iter()
            .filter_map(|x| {
                if x.is_kernel == kernel {
                    Some(x.count)
                } else {
                    None
                }
            })
            .sum()
    }

    fn unique_addresses(&self) -> usize {
        self.entries.len()
    }

    fn addresses_by_type(&self, kernel: bool) -> usize {
        self.entries
            .iter()
            .filter(|x| x.is_kernel == kernel)
            .count()
    }

    fn footprint(&self) -> usize {
        self.buckets[&PageSize::Pte].len() * 4096
    }

    fn footprint_by_type(&self, kernel: bool) -> usize {
        self.buckets[&PageSize::Pte]
            .iter()
            .filter(|entry| entry.is_kernel == kernel)
            .collect::<Vec<_>>()
            .len()
            * 4096
    }

    fn print_stats(&self) {
        println!(
            "Sampled footprint: {}, Kernel: {}, Userspace: {}",
            size_to_str(self.footprint()),
            size_to_str(self.footprint_by_type(true)),
            size_to_str(self.footprint_by_type(false))
        );
        println!(
            "Total count: {}, Kernel: {}, Userspace: {}",
            self.total_count(),
            self.count_by_type(true),
            self.count_by_type(false)
        );
        println!(
            "Unique addreses: {}, Kernel: {}, Userspace: {}",
            self.unique_addresses(),
            self.addresses_by_type(true),
            self.addresses_by_type(false)
        );

        println!();

        PageSize::iter().for_each(|pagesize| {
            println!(
                "Total {} pages {}, first: {}",
                size_to_str(pagesize.bytes()),
                self.buckets[&pagesize].len(),
                self.buckets[&pagesize]
                    .get(0)
                    .unwrap_or(&TraceEntry::default())
            );
            println!(
                "{} pages with >=50% occupancy: {}",
                size_to_str(pagesize.bytes()),
                self.buckets[&pagesize]
                    .iter()
                    .filter(|x| x.occupancy() >= 50)
                    .count()
            );
        });

        println!();
    }

    fn populate_buckets(&mut self, pagesize: PageSize) {
        let mut pages: HashMap<usize, TraceEntry> = HashMap::new();

        let prev = PageSize::from_repr(pagesize as u8 - 1).unwrap_or(PageSize::Pte);
        let binding = self.buckets.get_mut(&prev).unwrap();

        let entries = match pagesize {
            PageSize::Pte => &mut self.entries,
            _ => binding,
        };

        entries.iter_mut().for_each(|entry: &mut TraceEntry| {
            let address = align(entry.address, pagesize.bytes(), false);
            pages
                .entry(address)
                .and_modify(|x| {
                    x.count += entry.count;
                    x.latencies.extend(entry.latencies.iter());
                    if pagesize != PageSize::Pte {
                        x.subentries += 1;
                        x.basepages += entry.basepages;
                    }
                })
                .or_insert(TraceEntry {
                    address,
                    is_kernel: entry.is_kernel,
                    count: entry.count,
                    latencies: entry.latencies.to_owned(),
                    is_compound: !matches!(pagesize, PageSize::Pte),
                    subentries: 1,
                    basepages: match pagesize {
                        PageSize::Pte => 1,
                        _ => entry.basepages,
                    },
                    size: Some(pagesize),
                });
        });

        self.buckets
            .get_mut(&pagesize)
            .unwrap()
            .extend(pages.into_values());
        self.buckets
            .get_mut(&pagesize)
            .unwrap()
            .sort_by(|a, b| b.cmp(a));
    }

    fn load(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut map = HashMap::new();
        let mut current = None;

        for line in io::BufReader::new(File::open(&self.file).unwrap()).lines() {
            let line = line.unwrap();
            let line = line.trim();

            let entry = MissTraceLine::try_from(line);
            if entry.is_err() {
                continue;
            }

            match entry.unwrap() {
                MissTraceLine::Address(address) => {
                    current = Some(address);
                    map.entry(address)
                        .and_modify(|entry: &mut TraceEntry| entry.count += 1)
                        .or_insert(TraceEntry {
                            address,
                            is_kernel: is_kernel_address(address),
                            count: 1,
                            latencies: vec![],
                            is_compound: false,
                            subentries: 0,
                            basepages: 0,
                            size: None,
                        });
                }
                MissTraceLine::Latency(latency) => {
                    map.entry(current.unwrap())
                        .and_modify(|entry| entry.latencies.push(latency))
                        .or_insert_with(|| panic!());
                }
            }
        }

        self.entries = map.values().cloned().collect();
        self.entries.sort_by(|a, b| b.cmp(a));
        PageSize::iter().for_each(|pgsz| {
            self.populate_buckets(pgsz);
        });

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let prev = env::args().nth(1).ok_or(USAGE)?;
    let next = env::args().nth(2).ok_or(USAGE)?;
    let order: u8 = env::args().nth(3).ok_or(USAGE)?.parse()?;
    let cutoff: usize = env::args().nth(4).ok_or(USAGE)?.parse()?;

    let mut p = Trace::new(PathBuf::from(prev));
    let mut n = Trace::new(PathBuf::from(next));

    p.load()?;
    n.load()?;

    let pgsz = PageSize::from_repr(order).unwrap();

    if p.buckets[&pgsz].len() + n.buckets[&pgsz].len() < cutoff {
        println!("-1");
        return Ok(());
    }

    let hp: HashSet<usize> = HashSet::from_iter(p.buckets[&pgsz].iter().map(|x| x.address));
    let hn = HashSet::from_iter(n.buckets[&pgsz].iter().map(|x| x.address));

    println!("{}", hn.intersection(&hp).count() * 100 / n.buckets[&pgsz].len());

   Ok(())
}
