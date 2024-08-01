use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::{env, usize};

use strum::{EnumCount, EnumIter, FromRepr, IntoEnumIterator};

const PAGE_OFFSET: usize = 0xffff000000000000;
const PAGE_SIZE: usize = 4096;

const USAGE: &str = "usage: ./online_greedy <input> <output> <target>";

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
            Self::Pmd => 512,
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

fn cmp_order(a: usize, b: usize) -> Ordering {
    let diff = if a >= b { a - b } else { b - a };

    if diff.checked_ilog10().unwrap_or(0) <= 1 {
        Ordering::Equal
    } else if a > b {
        Ordering::Greater
    } else {
        Ordering::Less
    }
}

impl Ord for TraceEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_order(self.count, other.count).then_with(|| {
            self.subentries.cmp(&other.subentries).then_with(|| {
                self.latencies
                    .iter()
                    .sum::<usize>()
                    .cmp(&other.latencies.iter().sum::<usize>())
            })
        })
    }
}

impl fmt::Display for TraceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} address: 0x{:x}, count: {}, entries: {}, occupancy: {:.2}%, basepages: {}",
            match self.size {
                Some(size) => format!("{:?}", size),
                None => "address".to_string(),
            },
            self.address,
            self.count,
            self.subentries,
            match self.size {
                Some(size) => self.subentries as f64 * 100.0 / size.subentries() as f64,
                None => 100.0,
            },
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
                    .filter(|x| (x.subentries as f64 / pagesize.subentries() as f64) >= 0.5)
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
                        x.subentries += match pagesize {
                            PageSize::Pmd => entry.basepages,
                            _ => 1,
                        };
                        x.basepages += entry.basepages;
                    }
                })
                .or_insert(TraceEntry {
                    address,
                    is_kernel: entry.is_kernel,
                    count: entry.count,
                    latencies: entry.latencies.to_owned(),
                    is_compound: !matches!(pagesize, PageSize::Pte),
                    subentries: match pagesize {
                        PageSize::Pmd => entry.basepages,
                        _ => 1,
                    },
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

        PageSize::iter().for_each(|pagesize| {
            self.populate_buckets(pagesize);
        });

        Ok(())
    }

    fn compute_hints(
        &self,
        outfile: &str,
        target: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut entries: Vec<TraceEntry> = vec![];

        PageSize::iter().rev().for_each(|pagesize| {
            if env::var("LESHY_VERBOSE").unwrap_or("".to_owned()).len() != 0 {
                println!("{pagesize:?}");
            }
            self.buckets[&pagesize].iter().for_each(|x| {
                if env::var("LESHY_VERBOSE").unwrap_or("".to_owned()).len() != 0 {
                    println!("{x:?}");
                }
                if x.subentries as f64 * 100.0 / pagesize.subentries() as f64 >= target as f64
                    && entries.iter().all(|e| {
                        x.address < e.address || x.address >= e.address + e.size.unwrap().bytes()
                    })
                {
                    entries.push(x.clone())
                }
            });
        });

        entries.sort_by(|a, b| b.cmp(a));

        if env::var("LESHY_VERBOSE").unwrap_or("".to_owned()).len() != 0 {
            PageSize::iter().for_each(|pagesize| {
                println!(
                    "{} {} pages",
                    entries
                        .iter()
                        .filter(|x| { x.size.unwrap() == pagesize })
                        .count(),
                    size_to_str(pagesize.bytes())
                )
            });
        }

        if env::var("LESHY_VERBOSE").unwrap_or("".to_owned()).len() != 0 {
            entries.iter().for_each(|entry| {
                println!("{entry} {}", entry.latencies.len());
            });
        }

        let result = entries
            .iter()
            .filter_map(|x| {
                if x.size.is_none() || x.size == Some(PageSize::Pte) {
                    None
                } else {
                    Some(format!(
                        "0x{:x}-0x{:x}",
                        x.address,
                        x.address + x.size.unwrap().bytes()
                    ))
                }
            })
            .collect::<Vec<_>>();

        fs::write(outfile, result.join("\n"))?;

        if env::var("LESHY_VERBOSE").unwrap_or("".to_owned()).len() != 0 {
            println!(
                "count: {}, target: {target}, total: {}",
                entries.iter().map(|entry| entry.count).sum::<usize>(),
                entries.len()
            );
            println!();
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = env::args().nth(1).ok_or(USAGE)?;
    let output = env::args().nth(2).ok_or(USAGE)?;
    let target: usize = env::args().nth(3).ok_or(USAGE)?.parse()?;

    let mut trace = Trace::new(PathBuf::from(input));

    trace.load()?;
    if env::var("LESHY_VERBOSE").unwrap_or("".to_owned()).len() != 0 {
        trace.print_stats();
    }

    trace.compute_hints(&output, target)?;

    Ok(())
}
