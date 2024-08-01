use inotify::{Inotify, WatchMask};
use itertools::Itertools;
use lazy_static::lazy_static;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use procfs;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    env, fs,
    io::{self, prelude::*, BufReader},
    process::{self, Command, Stdio},
    thread,
    time::{Duration, Instant},
    fmt,
};
use strum::{EnumCount, FromRepr};

const SYSFS_HPMD_SIZE: &'static str = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size";
const SYSFS_KHUGE_SCANPAGES: &'static str = "/sys/kernel/mm/transparent_hugepage/khugepaged/pages_to_scan";
const SYSFS_KHUGE_SLEEP: &'static str = "/sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs";
const SYSFS_COALA_KHUGE: &'static str = "/sys/module/coalapaging/parameters/khugepaged";

const USAGE: &str = "usage: ./oleshy <pid>";
const PERF: &str = "/root/psomas/asplos24-etleshy/src/linux/tools/perf/perf";
const SLEEP_SEC: u64 = 2;
const EPOCHS: usize = 2;
const THRESHOLD: usize = 20;
const TLBSIZE: usize = 1280;

lazy_static! {
    static ref PGSZ: usize = procfs::page_size() as _;
    static ref PMD_SIZE: u64 = fs::read_to_string(SYSFS_HPMD_SIZE)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    static ref KHUGE_SCANPAGES: u64 = fs::read_to_string(SYSFS_KHUGE_SCANPAGES)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    static ref KHUGE_SLEEP: u64 = fs::read_to_string(SYSFS_KHUGE_SLEEP)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    static ref PAGES_SCANNED: u64 = *KHUGE_SCANPAGES * SLEEP_SEC * 1000 / *KHUGE_SLEEP;
}

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

fn _align(n: usize, m: usize, up: bool) -> usize {
    assert!(m.is_power_of_two());
    let mut ret = n & !(m - 1);
    if up && (ret != n) {
        ret += m;
    }

    ret
}

fn align_up(n: usize, m: usize) -> usize {
    _align(n, m, true)
}

fn align_down(n: usize, m: usize) -> usize {
    _align(n, m, false)
}

fn scale(n: usize, i: usize) -> usize {
    let s = n * (100 - 5 * i); 
    let d = s / 100;

    if s > d * 100 {
        d + 1
    } else {
        d
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, EnumCount, FromRepr)]
enum Size {
    Pte = 0,
    ContPte,
    Pmd,
    ContPmd,
}

impl Size {
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
        self.nr_pages() * *PGSZ
    }

    fn align(&self, n: usize) -> usize {
        align_down(n, self.bytes())
    }
}

fn recurring(n: usize) -> bool {
    n & ((1 << EPOCHS) - 1) != 0
}

fn first(n: usize) -> bool {
    n & 1 != 0
}

struct State {
    dist: [usize; Size::COUNT],
    lvl: Size,
    initlvl: Size,
    nr: usize,
    step: usize,
    misses: usize,
    total: usize,
    addrs: HashSet<usize>,
    hints: Vec<Entry>,
    cutoff: usize,
}

enum LineType {
    Address,
    Latency,
}
use LineType::*;

#[derive(Copy, Clone, Eq, PartialEq)]
struct Entry {
    size: Size,
    base: usize,
    misses: usize,
    cumlat: usize,
    subentries: usize,
    epochs: usize,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.misses.cmp(&other.misses).then_with(|| {
            self.cumlat
                .cmp(&other.cumlat)
                .then_with(|| self.subentries.cmp(&other.subentries))
        })
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "entry@{:x}, {:?}, misses: {}, cumlat: {}, subentries: {}, epochs: {:b}",
				self.base, self.size, self.misses, self.cumlat, self.subentries, self.epochs)
    }
}

struct Profiler {
    pid: u32,
    comm: String,
    epoch: usize,
    misses: [Vec<Entry>; EPOCHS],
    hints: [Vec<Entry>; EPOCHS],
    skip: Vec<Entry>,
}

impl Profiler {
    fn new(pid: u32, comm: String) -> Self {
        println!("Creating profiler for {}", &comm);
        Profiler {
            pid,
            comm,
            epoch: 0,
            misses: std::array::from_fn(|_| vec![]),
            hints: std::array::from_fn(|_| vec![]),
            skip: vec![],
        }
    }

    fn parse_line(line: Result<String, io::Error>, kind: LineType) -> usize {
        let line = line.unwrap();
        let line = line.trim();

        match kind {
            Address => usize::from_str_radix(line.strip_prefix("0x").unwrap(), 16)
                .map_err(|_| "invalid hex")
                .unwrap(),
            Latency => line.parse::<usize>().unwrap(),
        }
    }

    fn parse_address(line: Result<String, io::Error>) -> usize {
        Self::parse_line(line, LineType::Address)
    }

    fn parse_latency(line: Result<String, io::Error>) -> usize {
        Self::parse_line(line, LineType::Latency)
    }

    fn populate_bucket(&self, sz: usize, prev: &Vec<Entry>) -> Vec<Entry> {
        let tsz = Size::from_repr(sz as u8).unwrap();

        let mut entries: HashMap<usize, Entry> = HashMap::new();
        prev.iter().for_each(|entry: &Entry| {
            let base = tsz.align(entry.base);
            entries
                .entry(base)
                .and_modify(|x| {
                    x.misses += entry.misses;
                    x.cumlat += entry.cumlat;
                    x.subentries += 1;
                    x.epochs |= entry.epochs;
                })
                .or_insert(Entry {
                    base,
                    misses: entry.misses,
                    cumlat: entry.cumlat,
                    subentries: 1,
                    epochs: entry.epochs,
                    size: tsz,
                });
        });

        entries.into_values().collect()
    }

    fn write_hints(&self, hints: &[Entry]) {
        (0..Size::COUNT).for_each(|sz| {
            let sz = Size::from_repr(sz as u8).unwrap();
            println!(
                "{} {}",
                hints 
                    .iter()
                    .filter(|h| { h.size == sz})
                    .count(),
                size_to_str(sz.bytes())
            )
        });

        let out = hints 
            .iter()
            .map(|h| {
                format!(
                    "0x{:x}-0x{:x}",
                    h.base,
                    h.base + h.size.bytes()
                )
            })
            .collect::<Vec<_>>();

        let outf = format!("{}.{}.hints", self.comm, self.epoch);
        fs::write(&outf, out.join("\n")).unwrap();

        println!(
            "misses covered: {}, nrhints: {}",
            hints.iter().map(|h| h.misses).sum::<usize>(),
            hints.len()
        );


        fs::write(format!("/proc/{}/coala_hints", self.pid), "1").unwrap();
        Command::new("prctl")
            .args(["--ca", "--et", "--hints", &outf, &format!("{}", self.pid)])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        Command::new("prctl")
            .args(["--khuge", "--hints", &outf, &format!("{}", self.pid)])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        fs::write(SYSFS_COALA_KHUGE, "1").unwrap();
    }

    fn solve(&self, state: State, buckets: [Vec<Entry>; Size::COUNT]) -> Option<Vec<Entry>> {
        let lvl = state.lvl;
        let prev = Size::from_repr((lvl as usize - state.cutoff - 1) as u8);
        if prev.is_none() {
            return None;
        }
        let prev = prev.unwrap();

        let mut dist = state.dist;
        let mut rem = TLBSIZE - dist[(lvl as u8 + 1) as usize..].iter().sum::<usize>();

        let rem_entries = buckets[lvl as usize]
            .iter()
            .filter(|entry| {
                (0..Size::COUNT).rev().skip(Size::ContPmd as usize - state.initlvl as usize)
                    .all(|sz| !state.addrs.contains(&Size::from_repr(sz as u8).unwrap().align(entry.base)))
            })
            .take(rem).collect::<Vec<_>>();
        let rem_count = rem_entries.iter().map(|entry| entry.misses).sum::<usize>();

        if state.misses + rem_count < state.total {
            return None;
        }

        rem = rem.min(rem_entries.len());

        let mut n = state.nr;
        if n == 0 {
            n = rem;
        }

        let level_entries = buckets[lvl as usize]
            .iter()
            .filter(|entry| {
                (0..Size::COUNT).rev().skip(Size::ContPmd as usize - state.initlvl as usize)
                    .all(|sz| !state.addrs.contains(&Size::from_repr(sz as u8).unwrap().align(entry.base)))
            })
            .take(n)
            .collect::<Vec<_>>();
        dist[lvl as usize] = level_entries.len();

        loop {
            let mut count = state.misses;
            let mut addresses = state.addrs.clone();
            let mut entries = state.hints.clone();

            level_entries
                .iter()
                .take(dist[lvl as usize])
                .for_each(|&entry| {
                    count += entry.misses;
                    addresses.insert(entry.base);
                    entries.push(entry.clone());
                });

            if count >= state.total {
                return Some(entries);
            }

            if lvl as u8 == state.initlvl as u8 - 1 || lvl == Size::ContPte {
                let mut new_count = count;
                let mut new_addresses = addresses.clone();
                let mut new_entries = entries.clone();

                buckets[prev as usize]
                    .iter()
                    .filter(|entry| {
                        (0..Size::COUNT).rev().skip(Size::ContPmd as usize - state.initlvl as usize)
                            .all(|sz| !addresses.contains(&Size::from_repr(sz as u8).unwrap().align(entry.base)))
                    })
                    .take(rem - dist[lvl as usize])
                    .for_each(|entry| {
                        new_count += entry.misses;
                        new_addresses.insert(entry.base);
                        new_entries.push((*entry).clone());
                    });

                if new_count >= state.total {
                    return Some(new_entries);
                }
            } else {
                let new = State {
                    dist: dist.clone(),
                    lvl: Size::from_repr(lvl as u8 - 1).unwrap(),
                    initlvl: state.initlvl,
                    nr: 0,
                    total: state.total,
                    step: 8,
                    misses: count,
                    addrs: addresses.clone(),
                    hints: entries.clone(),
                    cutoff: if state.cutoff > 0 { state.cutoff - 1 } else { 0 },
                };

                let solution = self.solve(new, buckets.clone());
                if solution.is_some() {
                    return solution;
                }
            }

            if state.nr == 0 {
                dist[lvl as usize] += state.step;
                if dist[lvl as usize] > rem.min(level_entries.len()) {
                    return None;
                }
            } else {
                if dist[lvl as usize] < state.step {
                    return None;
                }
                dist[lvl as usize] -= state.step;
            }
        }
    }

    fn populate_buckets(&mut self) -> [Vec<Entry>; Size::COUNT] {
        let mut buckets: [Vec<Entry>; Size::COUNT] = std::array::from_fn(|_| vec![]);
        let idx = self.epoch % EPOCHS;

        let mut entries: HashMap<usize, Entry> = HashMap::new();
        for i in 0..EPOCHS {
            self.misses[(i + idx) % EPOCHS].iter().for_each(|entry| {
                let base = entry.base;
                let misses = scale(entry.misses, i);
                let lat = scale(entry.cumlat, i);

                entries
                    .entry(base)
                    .and_modify(|entry| {
                        entry.misses += misses;
                        entry.cumlat += lat;
                        entry.epochs |= 1 << i;
                    })
                    .or_insert(Entry {
                        base,
                        misses,
                        cumlat: lat,
                        subentries: 1,
                        epochs: 1 << i,
                        size: Size::Pte,
                    });
            });
        }

        buckets[Size::Pte as usize] = entries.into_values().collect();
        buckets[Size::Pte as usize].sort_by(|a, b| b.cmp(a));

        (Size::ContPte as usize..Size::COUNT).for_each(|sz| {
            buckets[sz] = self.populate_bucket(sz, &buckets[sz as usize - 1]);
            buckets[sz].sort_by(|a, b| b.cmp(a));
        });

        buckets
    }

    fn should_retain(&mut self, entry: &Entry) -> bool {
        if first(entry.epochs) {
            self.skip.retain(|x| !(x.base == entry.base && x.size == entry.size));
            return true
        }

        if self.skip.iter().any(|x| x.base == entry.base && x.size == entry.size) {
            println!("skipping {entry:?} due to skip");
            return false
        }

        for i in 1..Size::COUNT {
            let epoch = (i + self.epoch) % EPOCHS;
            if self.hints[epoch].iter().all(|x| !(x.base == entry.base && x.size == entry.size)) {
                return true
            }
        }

        println!("skipping {entry:?}, setting skip");
        self.skip.push(entry.clone());
        return false
    }

    fn finalize(&mut self, hints: Vec<Entry>, buckets: [Vec<Entry>; Size::COUNT]) {
        let now = Instant::now();
        let mut res: Vec<Entry> = vec![];

        for hint in hints.into_iter() {
            if hint.subentries > 1 && self.should_retain(&hint) {
                res.push(hint);
                continue;
            }

            'outer: for sz in (0..(hint.size as usize).saturating_sub(1)).rev() {
                for entry in buckets[sz].iter() {
                    if hint.size.align(entry.base) == hint.base {
                        if entry.subentries > 1 && self.should_retain(entry) {
                            println!("Falling back from {hint:?} to {entry:?}"); 
                            res.push(*entry);
                            break 'outer;
                        } else {
                            continue 'outer;
                        }
                    }
                }
            }
        }

        //res.sort_by(|a, b| b.cmp(a));
        let mut n = 0;
        let mut nr = 0;
        let mut scanned = 0;
        for hint in res.iter() {
            n += hint.size.nr_pages();
            nr += 1;

            if scanned == 0 && n >= *PAGES_SCANNED as _ {
                scanned = nr;
            }

            if n >= *PAGES_SCANNED as usize * 2 {
                break;
            }
        }

        self.write_hints(&res[..nr]);
        self.hints[self.epoch % EPOCHS] = res[..scanned].to_vec();

        let elapsed = now.elapsed();
        println!(
            "Finalized in {}ms", elapsed.as_millis()
        );
    }

    fn generate_hints(&mut self, buckets: [Vec<Entry>; Size::COUNT]) {
        let total_misses: usize = buckets[Size::Pte as usize]
            .iter()
            .map(|x| x.misses)
            .sum();

        let (initsz, initnr) = (0..Size::COUNT).filter_map(|x| {
            let sz = Size::from_repr(x as u8).unwrap();
            let nr = buckets[x].len();
            if nr <= TLBSIZE {
                Some((sz, nr))
            } else {
                None
            }
        }).nth(0).unwrap_or((Size::ContPmd, buckets[Size::ContPmd as usize].len()));

        if initsz == Size::Pte {
            println!("PTE-only hints, skipping");
            return;
        };

        if initnr * initsz.nr_pages() > *PAGES_SCANNED as usize * THRESHOLD {
            let hints = buckets[initsz as usize][..initnr].to_owned();
            self.finalize(hints, buckets);
            return;
        }

        let mut hints = None;
        let mut cutoff = 0;
        loop {
            let mut nr = initnr;
            loop {
                let state = State {
                    dist: [0; Size::COUNT],
                    lvl: initsz,
                    initlvl: initsz,
                    nr: nr,
                    step: 1,
                    misses: 0,
                    total: total_misses,
                    addrs: HashSet::new(),
                    hints: vec![],
                    cutoff,
                };

                let res = self.solve(state, buckets.clone());
                if res.is_none() {
                    break;
                }

                let res = res.unwrap();
                nr = res.iter().filter(|h| h.size == initsz).count();
                nr -= 1;

                hints = Some(res);
            }

            if hints.is_none() {
                if cutoff > Size::COUNT - 1 {
                    panic!("no solution!");
                }
                cutoff += 1;
                continue;
            }
            break;
        }

        let hints = hints.unwrap();
        self.finalize(hints, buckets);
    }

    fn ingest<I>(&mut self, epoch: usize, lines: I)
    where
        I: Iterator<Item = Result<String, io::Error>>,
    {
        println!("Ingesting snapshot {}.{epoch}", &self.comm);
        self.epoch = epoch;
        let idx = epoch % EPOCHS;

        let mut entries: HashMap<usize, Entry> = HashMap::new();
        for (addr, lat) in lines.tuples() {
            let addr = Self::parse_address(addr);
            let base = Size::Pte.align(addr);
            let lat = Self::parse_latency(lat);

            entries
                .entry(base)
                .and_modify(|entry| {
                    entry.misses += 1;
                    entry.cumlat += lat;
                })
                .or_insert(Entry {
                    base,
                    misses: 1,
                    cumlat: lat,
                    subentries: 1,
                    epochs: 0,
                    size: Size::Pte,
                });
        }

        self.misses[idx] = entries.into_values().collect();

        let now = Instant::now();
        let buckets = self.populate_buckets();
        let elapsed = now.elapsed();
        println!(
            "Buckets populated in in {}ms (total elements: {})",
            elapsed.as_millis(),
            self.misses.iter().map(|x| x.len()).sum::<usize>()
        );
        let now = Instant::now();
        self.generate_hints(buckets);
        let elapsed = now.elapsed();
        println!(
            "Hints computed in in {}ms", elapsed.as_millis()
        );
    }
}

fn run_profiler(sampler_pid: u32, pid: u32, comm: String) {
    let mut epoch = 0;
    let dest = format!("./{comm}.raw");
    let mut reporter = Command::new(PERF);
    reporter
        .env("DUMP", "1")
        .arg("report")
        .arg("--quiet")
        .arg("--stdio")
        .args(["-i", &dest])
        .stdout(Stdio::piped());

    let mut profiler = Profiler::new(pid, comm.to_owned());

    let mut sleep_duration = Duration::from_secs(SLEEP_SEC);
    loop {
        thread::sleep(sleep_duration);
        println!("Taking snapshot...");
        let mut inotify = Inotify::init().unwrap();
        inotify
            .watches()
            .add(format!("./"), WatchMask::CLOSE_WRITE)
            .unwrap();
        signal::kill(Pid::from_raw(sampler_pid as _), Signal::SIGUSR2).unwrap();

        let mut buffer = [0u8; 4096];
        let evt = inotify
            .read_events_blocking(&mut buffer)
            .unwrap()
            .next()
            .unwrap();
        let source = evt.name.unwrap();
        inotify.watches().remove(evt.wd).unwrap();

        println!("New snapshot ({} -> {dest})...", &source.to_str().unwrap());
        fs::rename(&source, &dest).unwrap();

        let now = Instant::now();

        let mut reporter = reporter.spawn().unwrap();
        let reader = BufReader::new(reporter.stdout.take().unwrap());

        profiler.ingest(epoch, reader.lines());

        let elapsed = now.elapsed();
        println!(
            "Processed snapshot {comm}.{epoch} in {}ms",
            elapsed.as_millis()
        );
        sleep_duration = Duration::from_secs(SLEEP_SEC).saturating_sub(elapsed);

        reporter.wait().unwrap();
        epoch += 1;
    }
}

fn run_leshy(pid: u32, comm: String) {
    let sampler = Command::new(PERF)
        .arg("record")
        .args(["-c", "1024"])
        .args(["-e", "arm_spe/jitter=1,event_filter=0x20/"])
        .arg("--no-switch-events")
        .arg("--switch-output=signal")
        .args(["-p", &pid.to_string()])
        .spawn()
        .unwrap();

    let sampler_pid: u32 = sampler.id();
    println!("Spawned sampler with pid {}", sampler_pid);

    thread::spawn(move || {
        run_profiler(sampler_pid, pid, comm);
        println!("profiler exited!");
        process::exit(1);
    });

    sampler.wait_with_output().unwrap();
    println!("sampler exited!");
    process::exit(1);
}

fn main() {
    let pid: u32 = env::args().nth(1).ok_or(USAGE).unwrap().parse().unwrap();
    let comm = procfs::process::Process::new(pid as _)
        .unwrap()
        .stat()
        .unwrap()
        .comm;

    println!("Enabling Leshy for {pid} ({comm})");
    run_leshy(pid, comm);
    unreachable!("shouldn't ever reach this");
}
