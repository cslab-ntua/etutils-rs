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

#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
enum TraceType {
    MissTrace = 0,
    AccessTrace,
}

#[derive(Clone, Copy, Debug)]
struct Coverage {
    count: usize,
    nr_entries: usize,
}

#[derive(Clone, Debug)]
struct Trace {
    file: PathBuf,
    tlbsize: usize,
    entries: Vec<TraceEntry>,
    buckets: HashMap<PageSize, Vec<TraceEntry>>,
    coverage: HashMap<PageSize, Coverage>,
    trace_type: TraceType,
    count: usize,
}

impl Trace {
    fn new(file: PathBuf, tlbsize: usize, trace_type: TraceType) -> Self {
        let mut buckets = HashMap::new();
        PageSize::iter().for_each(|pagesize| {
            buckets.insert(pagesize, vec![]);
        });

        Self {
            file,
            tlbsize: tlbsize,
            entries: vec![],
            buckets,
            coverage: HashMap::new(),
            trace_type,
            count: 0,
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

        match self.trace_type {
            TraceType::MissTrace => {
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
            }
            TraceType::AccessTrace => {
                for line in io::BufReader::new(File::open(&self.file).unwrap()).lines() {
                    let line = line.unwrap();
                    let line = line.trim().split("->").collect::<Vec<_>>();

                    if line.len() != 2 {
                        continue;
                    }

                    let pfn = usize::from_str_radix(line[0].trim().strip_prefix("0x").unwrap(), 16);
                    let hits = line[1].trim().parse::<usize>();

                    if pfn.is_err() || hits.is_err() {
                        continue;
                    }

                    let pfn = pfn.unwrap();
                    let address = pfn * PAGE_SIZE;
                    let hits = hits.unwrap();

                    map.entry(pfn)
                        .and_modify(|entry| entry.count += hits)
                        .or_insert(TraceEntry {
                            address,
                            is_kernel: is_kernel_address(address),
                            count: hits,
                            latencies: vec![],
                            is_compound: false,
                            subentries: 0,
                            basepages: 0,
                            size: None,
                        });
                }
            }
        }

        self.entries = map.values().cloned().collect();
        self.entries.sort_by(|a, b| b.cmp(a));

        for pagesize in PageSize::iter() {
            self.populate_buckets(pagesize);
        }

        self.count = self.total_count();

        Ok(())
    }

    fn profile(&mut self, target: usize) -> Result<(), Box<dyn std::error::Error>> {
        if env::var("LESHY_VERBOSE").unwrap_or("".to_owned()).len() != 0 {
            self.print_stats();
        }

        for pagesize in PageSize::iter() {
            let mut nr_entries = 0;
            let mut count = 0;

            for entry in self.buckets[&pagesize].iter() {
                count += entry.count;
                nr_entries += 1;

                if nr_entries >= self.tlbsize || count >= target {
                    break;
                }
            }

            if env::var("LESHY_VERBOSE").unwrap_or("".to_owned()).len() != 0 {
                println!(
                    "Coverage with the {nr_entries} most frequent {} entries is {:.4}%",
                    size_to_str(pagesize.bytes()),
                    count as f64 * 100.0 / self.total_count() as f64
                );

                println!("Top 10 entries:");
                self.buckets[&pagesize].iter().take(10).for_each(|entry| {
                    println!("{entry}");
                });
                if pagesize == PageSize::Pte {
                    continue;
                }

                println!("Top 10 entries (excluding single-subentry):");
                self.buckets[&pagesize].iter().filter(|x| x.subentries > 1).take(10).for_each(|entry| {
                    println!("{entry}");
                });
            }

            self.coverage
                .insert(pagesize, Coverage { count, nr_entries });
        }

        Ok(())
    }

    fn compute_hints(
        &self,
        outfile: &str,
        target: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (&start_pgsz, coverage) = self
            .coverage
            .iter()
            .filter(|(k, v)| v.count >= target)
            .min_by_key(|&(&k, &v)| k as u8)
            .unwrap_or((&PageSize::ContPmd, &self.coverage[&PageSize::ContPmd]));

        if start_pgsz == PageSize::Pte || start_pgsz == PageSize::ContPte {
            return Ok(())
        }

        let target = target.min(coverage.count);

        let mut pgsz = start_pgsz;

        let mut entries = vec![];
        let mut n = 0;
        let mut count = 0;

        loop {
            for entry in self.buckets[&pgsz].iter().filter(|x| x.subentries > 1) {
                entries.push(entry.clone());
                count += entry.count;
                n += 1;

                let prev_pgsz = PageSize::from_repr(pgsz as u8 - 1).unwrap();
                let remaining = self.buckets[&prev_pgsz].iter().filter(|x| {
                    entries.iter().all(|e| e.address != align(x.address, e.size.unwrap().bytes(), false))
                }).take(self.tlbsize - n).map(|x| x.count).sum::<usize>();

                if remaining + count >= target {
                    break;
                }
            }

            if pgsz == PageSize::Pmd {
                break;
            }

            pgsz = PageSize::from_repr(pgsz as u8 - 1).unwrap();
        }

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
                Some(format!(
                    "0x{:x}-0x{:x}",
                    x.address,
                    x.address + x.size.unwrap().bytes()
                ))
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
    let slack: usize = env::args().nth(4).ok_or(USAGE)?.parse()?;

    let trace_type = if input.contains("access") {
        TraceType::AccessTrace
    } else {
        TraceType::MissTrace
    };

    let tlbsize = TLBSIZE * slack / 100;
    let mut trace = Trace::new(PathBuf::from(input), tlbsize, trace_type);

    trace.load()?;

    let mut target = trace.total_count() * target / 100000;
    if trace.total_count() * target % 100000 != 0 {
        target += 1;
    }

    trace.profile(target)?;
    trace.compute_hints(&output, target)?;

    Ok(())
}
