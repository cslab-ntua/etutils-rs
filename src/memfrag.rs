use memmap2::{Advice, MmapOptions, MmapRaw};
use nix::unistd::pause;
use std::{env, fmt::Debug, fs, str::FromStr};
use rand::prelude::*;

const FMFI_PATH: &str = "/sys/kernel/debug/extfrag/unusable_index";
const CA_BUDDYINFO_PATH: &str = "/proc/capaging/buddyinfo";
const BUDDYINFO_PATH: &str = "/proc/buddyinfo";
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

enum FileFormat {
    Linux,
    Capaging,
}

impl FileFormat {
    fn filter(&self, line: &str, node: usize) -> bool {
        line.contains("Normal")
            && match self {
                FileFormat::Linux => line.contains(&format!("Node {}", node)),
                FileFormat::Capaging => {
                    line.contains(&format!("node: {}", node)) && line.contains("Movable")
                }
            }
    }

    fn extract(&self, line: String) -> String {
        match self {
            FileFormat::Linux => line,
            FileFormat::Capaging => line.rsplit(',').next().unwrap().to_owned(),
        }
    }

    fn parse<T>(&self, input: String, node: usize) -> Vec<T>
    where
        T: FromStr,
        T::Err: Debug,
    {
        input
            .lines()
            .find_map(|line| {
                if self.filter(line, node) {
                    Some(
                        self.extract(line.to_owned())
                            .split_whitespace()
                            .filter_map(|x| x.parse::<T>().ok())
                            .collect::<Vec<T>>(),
                    )
                } else {
                    None
                }
            })
            .unwrap()
    }
}

fn fmfi(node: usize, order: usize) -> (usize, f64) {
    let fmfi = FileFormat::Linux.parse(fs::read_to_string(FMFI_PATH).unwrap(), node);
    let buddyinfo = FileFormat::Linux.parse(fs::read_to_string(BUDDYINFO_PATH).unwrap(), node);

    if order > buddyinfo.len() {
        let ca_buddyinfo: Vec<usize> =
            FileFormat::Capaging.parse(fs::read_to_string(CA_BUDDYINFO_PATH).unwrap(), node);

        let total = buddyinfo
            .iter()
            .enumerate()
            .fold(0, |acc, (ord, pages)| acc + (1 << ord) * pages);

        let pages = if order == 13 {
            ca_buddyinfo[0]
        } else {
            assert!(order == 18);
            ca_buddyinfo[1]
        } * (1 << order);

        let order_fmfi = ((total - pages) as f64) / (total as f64);
        return (pages, order_fmfi);
    }

    (
        buddyinfo[order..]
            .iter()
            .enumerate()
            .fold(0, |acc, (ord, pages)| {
                acc + (1usize << (order + ord)) * pages
            }),
        *fmfi.get(order).unwrap(),
    )
}

fn align(n: usize, s: usize) -> usize {
    assert!(s.is_power_of_two());
    let m = s - 1;
    if n & m != 0 {
        (n + s) & !m
    } else {
        n
    }
}

fn freemem(node: usize) -> usize {
    FileFormat::Linux
        .parse(fs::read_to_string(BUDDYINFO_PATH).unwrap(), node)
        .iter()
        .enumerate()
        .fold(0, |acc, (ord, pages)| acc + (1usize << (12 + ord)) * pages)
}

fn getenv<T>(key: &str, default: T) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    match env::var(key) {
        Ok(val) => val.parse::<T>().unwrap(),
        Err(_) => default,
    }
}

fn over_target(node: usize, order: usize, target: usize) -> bool {
    let fragpct = fmfi(node, order).1;
    target <= ((fragpct * 100.0) as usize)
}

fn release(buf: &MmapRaw, offset: usize, len: usize) {
    unsafe {
        buf.advise_range(Advice::free(), offset, len).unwrap();
        buf.advise_range(Advice::dont_need(), offset, len).unwrap();
        buf.advise_range(Advice::normal(), offset, len).unwrap();
    }
}

fn main() {
    let node = getenv("FRAG_NODE", 0);

    let order = getenv("FRAG_ORDER", 9);
    let target = getenv("FRAG_TARGET", 99);

    let relax_order = getenv("FRAG_RELAX_ORDER", 13);
    assert!(relax_order >= order);
    let relax_order_size = 1 << (relax_order + 12);

    let press_order = getenv("FRAG_PRESS_ORDER", 0);
    assert!(order > press_order);
    let press_order_size = 1 << (press_order + 12);

    let release_size = getenv("FRAG_RELEASE", 80 << 30);
    let slack = getenv("FRAG_SLACK", 1 << 30);

    let _verbose = getenv("FRAG_VERBOSE", 0) == 1;

    let (_pages, fragpct) = fmfi(node, order);
    let free_size = freemem(node);
    let alloc_size = free_size - slack;

    println!(
        "Target FMFI: {target}%, Current FMFI: {:.2}%, Freemem: {}, Allocating: {}, Releasing: {}",
        fragpct * 100.0,
        size_to_str(free_size),
        size_to_str(alloc_size),
        size_to_str(release_size)
    );

    let buf = MmapRaw::from(
        MmapOptions::new()
            .len(alloc_size)
            .populate()
            .map_anon()
            .unwrap(),
    );

    buf.advise(Advice::no_huge_page()).unwrap();

    let start = buf.as_ptr() as usize;
    let end = start + alloc_size;

    let mut released = 0;

    let mut rng = rand::thread_rng();

    let mut press_idxs: Vec<usize> = (0..(alloc_size / press_order_size)).step_by(2).collect();
    let mut _press_idxs: Vec<usize> = (0..(alloc_size / press_order_size)).skip(1).step_by(2).collect();
    let mut relax_idxs: Vec<usize> = (0..(alloc_size / relax_order_size)).step_by(2).collect();
    let mut _relax_idxs: Vec<usize> = (0..(alloc_size / relax_order_size)).skip(1).step_by(2).collect();

    press_idxs.extend(_press_idxs);
    relax_idxs.extend(_relax_idxs);

    let mut addr = start;
    let mut relax_end = false;
    loop {
        if released >= release_size {
            break;
        }

        if target == 999 || !over_target(node, order, target) || relax_end {
            addr = align(addr, press_order_size);

            if addr + press_order_size > end {
                break;
            }

            let idx = (addr - start) / press_order_size;
            press_idxs.remove(press_idxs.iter().position(|x| *x == idx).unwrap());

            release(&buf, addr - start, press_order_size);
            released += press_order_size;
            addr += 2 * press_order_size;
        } else if !relax_end {
            addr = align(addr, relax_order_size);

            if addr + relax_order_size > end {
                relax_end = true;
                continue;
            }

            let idx = (addr - start) / relax_order_size;
            relax_idxs.remove(relax_idxs.iter().position(|x| *x == idx).unwrap());

            release(&buf, addr - start, relax_order_size);
            released += relax_order_size;
            addr += relax_order_size;
        }
    }

    while freemem(node) < release_size {
        if target == 999 || !over_target(node, order, target) {
            if press_idxs.len() == 0 {
                break;
            }
            let idx = press_idxs.pop().unwrap();
            let addr = idx * press_order_size;

            if addr + press_order_size > end {
                continue;
            }

            release(&buf, addr, press_order_size);
            released += press_order_size;
        } else {
            if relax_idxs.len() == 0 {
                break;
            }
            let idx = relax_idxs.pop().unwrap();
            let addr = idx * relax_order_size;

            if addr + relax_order_size > end {
                continue;
            }

            release(&buf, addr, relax_order_size);
            released += relax_order_size;
        }
    }

    println!("Remaining freemem: {}, released: {}", size_to_str(freemem(node)), size_to_str(released));
    pause();
}
