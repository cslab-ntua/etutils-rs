use clap::Parser;
use libc::{iovec, syscall, SYS_pidfd_open, SYS_process_madvise};
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::ops::Range;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{self, Command};
use std::thread;
use std::time::Duration;

use nix::errno::Errno;

const MADV_ELASTIC: usize = 25;
const MADV_CAPAGING: usize = 26;

const MADV_PAGESIZE_64K: usize = 27;
const MADV_PAGESIZE_2M: usize = 28;
const MADV_PAGESIZE_32M: usize = 29;
const MADV_KHUGE: usize = 30;

const PAGE_SHIFT: usize = 12;
const PAGE_MASK: usize = !((1 << PAGE_SHIFT) - 1);
const MAX_RW_COUNT: usize = (i32::MAX & PAGE_MASK as i32) as usize;

const SYS_OHP_STATS: i64 = 451;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    hints: Option<PathBuf>,

    #[arg(long)]
    ca: bool,

    #[arg(long)]
    et: bool,

    #[arg(long)]
    hwk: bool,

    #[arg(long)]
    khuge: bool,

    #[arg(long)]
    only2m: bool,

    #[clap(required = true)]
    proc: Vec<String>,
}

fn update_mm_ohp_stats(pid: u32, val: usize) -> i64 {
    unsafe { syscall(SYS_OHP_STATS, pid, val) }
}

fn enable_hawkey(pid: u32) {
    println!("Enabling HawkEye for {pid}");
    update_mm_ohp_stats(pid, 1000);
}

fn pidfd_open(pid: u32, flags: usize) -> i64 {
    unsafe { syscall(SYS_pidfd_open, pid, flags) }
}

fn process_madvise(pidfd: i64, ranges: &[(usize, usize)], advice: usize, flags: usize) -> i64 {
    unsafe {
        let mut iovs: Vec<iovec> = ranges
            .iter()
            .map(|range| iovec {
                iov_base: range.0 as _,
                iov_len: range.1 as _,
            })
            .collect();

        syscall(
            SYS_process_madvise,
            pidfd,
            iovs.as_mut_ptr(),
            iovs.len(),
            advice,
            flags,
        )
    }
}

fn load_hints_khuge(pid: u32, hints: &PathBuf, only2m: bool) {
    let pidfd = pidfd_open(pid, 0);

    for line in io::BufReader::new(File::open(hints).unwrap()).lines() {
        let line = line.unwrap();

        let (start, end) = line.split_once('-').unwrap();

        let start = usize::from_str_radix(&start[2..], 16).unwrap();
        let end = usize::from_str_radix(&end[2..], 16).unwrap();
        
        if end - start == 4096 {
            continue;
        }

        if env::var("LESHYDBG").is_ok() {
            println!("Setting khuge mark for 0x{:x}", start);
        }

        if only2m {
            if end - start < 2 << 20 {
                continue;
            }
            if end - start > 2 << 20 {
                (start..end).step_by(2 << 20).for_each(|x| {
                    loop {
                        let ret = process_madvise(pidfd, &[(x, 4096)], MADV_KHUGE, 0);
                        if ret >= 0 {
                            break;
                        }

                        if Errno::last() == Errno::EAGAIN {
                            println!("sleeping...");
                            thread::sleep(Duration::from_millis(10000));
                        } else {
                            panic!();
                        }
                    }
                });
                continue;
            }

        }

        loop {
            let ret = process_madvise(pidfd, &[(start, 4096)], MADV_KHUGE, 0);
            if ret >= 0 {
                break;
            }

            if Errno::last() == Errno::EAGAIN {
                println!("sleeping...");
                thread::sleep(Duration::from_millis(10000));
            } else {
                panic!();
            }
        }
    }
}

fn load_hints(pid: u32, hints: &PathBuf, only2m: bool) {
    let mut ranges: Vec<Range<usize>> = vec![];
    let pidfd = pidfd_open(pid, 0);

    for line in io::BufReader::new(File::open(hints).unwrap()).lines() {
        let line = line.unwrap();

        let (start, end) = line.split_once('-').unwrap();

        let start = usize::from_str_radix(&start[2..], 16).unwrap() >> PAGE_SHIFT;
        let end = usize::from_str_radix(&end[2..], 16).unwrap() >> PAGE_SHIFT;
        let size = end - start;

/*
        assert!(ranges
            .iter()
           .all(|range| !range.contains(&start) && !range.contains(&(end - 1))));
*/
        if ranges.iter()
           .any(|range| range.contains(&start) || range.contains(&(end - 1))) {
            println!("Overlapping range detected for 0x{start:x} {}", size.ilog2());
            continue; 
        }
        
        if only2m {
            if size < 512 {
                continue;
            }
            if size > 512 {
                (start..end).step_by(512).for_each(|x| {
                    ranges.push(x..x + 512);
                    if env::var("LESHYDBG").is_ok() {
                        println!("Adding 0x{:x} {}", x, 9);
                    }
                });
                continue;
            }
        }

        ranges.push(start..end);
        if env::var("LESHYDBG").is_ok() {
            println!("Adding 0x{:x} {}", start, size.ilog2());
        }
    }

    let orders: [(usize, usize); 3] = [
        (1 << 4, MADV_PAGESIZE_64K),
        (1 << 9, MADV_PAGESIZE_2M),
        (1 << 13, MADV_PAGESIZE_32M),
    ];

    for order in orders.iter().rev() {
        let chunk_size = unsafe { libc::sysconf(libc::_SC_IOV_MAX) as usize }
            .min(MAX_RW_COUNT / (order.0 << PAGE_SHIFT));

        ranges
            .iter()
            .filter_map(|range| {
                if range.end - range.start == order.0 {
                    Some((
                        range.start << PAGE_SHIFT,
                        (range.end - range.start) << PAGE_SHIFT,
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .chunks(chunk_size)
            .for_each(|chunk| {
                //assert!(process_madvise(pidfd, chunk, order.1, 0) >= 0);
                if process_madvise(pidfd, chunk, order.1, 0) < 0 {
                    println!("failed to load chunk");
                }
            });
    }
}

fn enable_capaging(pid: u32, ca: bool, et: bool, hints: &Option<PathBuf>, only2m: bool) {
    match hints {
        Some(hints) => {
            println!("Enabling hints for {pid}");
            load_hints(pid, hints, only2m);
        },
        None => (),
    }

    let pidfd = pidfd_open(pid, 0);
    if ca {
        println!("Enabling CAPaging for {pid}");
        assert!(process_madvise(pidfd, &[(0, 4096)], MADV_CAPAGING, 0) >= 0);
    }

    if et {
        println!("Enabling ET for {pid}");
        assert!(process_madvise(pidfd, &[(0, 4096)], MADV_ELASTIC, 0) >= 0);
    }
}

fn main() {
    let args = Args::parse();
    let mode = args.proc[0].parse::<u32>().is_ok();

    if mode {
        for p in args.proc.iter() {
            let p = p.parse::<u32>().unwrap();
            if args.hwk {
                enable_hawkey(p);
            }
            if args.ca || args.et {
                enable_capaging(p, args.ca, args.et, &args.hints, args.only2m);
            }

            if args.khuge {
                load_hints_khuge(p, &args.hints.clone().unwrap(), args.only2m);
            }
        }
    } else {
        let p = process::id();
        if args.hwk {
            enable_hawkey(p);
        }
        if args.ca || args.et {
            enable_capaging(p, args.ca, args.et, &args.hints, args.only2m);
        }

        Command::new(args.proc[0].to_owned()).args(&args.proc[1..]).exec();
    }
}
