use lazy_static::lazy_static;
use libc;
use rand::prelude::*;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::{env, fs, thread};

const SYSFS_HPMD_SIZE: &str = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size";
const SYSFS_EVENTS: &str = "/sys/kernel/tracing/events";
const TRIGGER: &str = "hist:keys=cycles.buckets=1:vals=hitcount:size=8192:sort=cycles";

lazy_static! {
    static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    static ref HPMD_SIZE: usize = fs::read_to_string(SYSFS_HPMD_SIZE)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
}

fn align(n: usize, s: usize) -> usize {
    assert!(s.is_power_of_two());
    let m = !(s - 1);
    if n & m != 0 {
        (n + s) & m
    } else {
        n
    }
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

fn create_vma(vma_size: usize) -> usize {
    let addr = unsafe {
        libc::mmap(
            0 as _,
            vma_size + 2 * *PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    } as usize;

    unsafe {
        libc::mmap(
            addr as _,
            *PAGE_SIZE,
            libc::PROT_NONE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
            -1,
            0,
        );
        libc::mmap(
            (addr + vma_size + *PAGE_SIZE) as _,
            *PAGE_SIZE,
            libc::PROT_NONE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
            -1,
            0,
        );
    };

    addr
}

fn drop_vma(addr: usize, vma_size: usize) {
    unsafe {
        libc::madvise(addr as _, vma_size, libc::MADV_DONTNEED);

        libc::madvise(addr as _, vma_size, libc::MADV_FREE);
    }
}

fn build_trigger(tids: &Vec<usize>, cont: bool, pause: bool) -> String {
    let first = tids[0];
    let mut trigger = format!(
        "{TRIGGER}{} if common_pid == {first}",
        if pause {
            ":pause"
        } else if cont {
            ":continue"
        } else {
            ""
        }
    );

    tids.iter().skip(1).for_each(|id| {
        trigger = format!("{trigger} || common_pid == {id}");
    });

    return trigger;
}

fn do_write(trigger_file: &str, trigger: &str) {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(trigger_file)
        .unwrap();
    file.write_all(trigger.as_bytes()).unwrap();
}

fn do_events(subsys: &str, trigger: &str) {
    let event_dir = format!("{SYSFS_EVENTS}/{subsys}");

    if !Path::new(&event_dir).is_dir() {
        return;
    }

    for event in fs::read_dir(event_dir).unwrap() {
        let path = event.unwrap().path();
        if !path.is_dir() {
            continue;
        }
        let path_str = path.as_path().to_str().unwrap();
        let trigger_file = format!("{path_str}/trigger");
        do_write(&trigger_file, trigger);
    }
}

fn do_tracing(tids: &Vec<usize>, enable: bool, first: bool) {
    let trigger = build_trigger(tids, !first, !enable);

    do_events("pftrace", &trigger);
    do_events("capaging", &trigger);
    do_events("et", &trigger);
}

fn start_tracing(tids: &Vec<usize>, first: bool) {
    do_tracing(tids, true, first);
}

fn stop_tracing(tids: &Vec<usize>) {
    do_tracing(tids, false, false);
}

fn main() {
    let vma_size = env::args().nth(1).unwrap().parse::<usize>().unwrap();
    let nr_vmas = env::args().nth(2).unwrap().parse::<usize>().unwrap();
    let nr_threads = env::args().nth(3).unwrap().parse::<usize>().unwrap();
    let shuffle = env::args().nth(4).unwrap().parse::<bool>().unwrap();
    let nr_faults = env::args().nth(5).unwrap().parse::<usize>().unwrap();
    let flush = env::args().nth(6).unwrap().parse::<bool>().unwrap();

    let fault_size = 64 * 1024;
    let vma_size = align(vma_size, fault_size);

    let faults_per_loop = vma_size / fault_size;
    let mut loops = nr_faults / faults_per_loop;

    if nr_faults % faults_per_loop != 0 {
        loops += 1
    }

    println!(
        "allocating {}, {} VMAs, {} per VMA, threads: {}, shuffle: {}, faults: {}, faults per loop: {}, loops: {}",
        size_to_str(vma_size * nr_vmas),
        nr_vmas,
        size_to_str(vma_size),
        nr_threads, shuffle, nr_faults, faults_per_loop, loops
    );

    let mut vmas: Vec<usize> = vec![];
    let mut pages: Vec<usize> = vec![];

    thread::scope(|s| {
        let mut txs: Vec<Sender<_>> = vec![];
        let mut threads = vec![];

        let (tid, rid) = channel();
        for _ in 0..nr_threads {
            let (tx, rx) = channel::<Arc<&[usize]>>();
            txs.push(tx);

            let tid = tid.clone();
            s.spawn(move || {
                tid.send(unsafe { libc::gettid() } as usize).unwrap();

                loop {
                    let chunk = rx.recv();
                    if chunk.is_err() {
                        break;
                    }

                    chunk
                        .unwrap()
                        .into_iter()
                        .for_each(|addr| unsafe { (*addr as *mut u8).write_bytes(0xff, 1) });

                    tid.send(0).unwrap();
                }
            });
        }

        for _ in 0..nr_threads {
            threads.push(rid.recv().unwrap());
        }

        for _ in 0..nr_vmas {
            let addr = create_vma(vma_size);
            pages.extend(
                (addr + *PAGE_SIZE..addr + *PAGE_SIZE + vma_size)
                    .step_by(fault_size)
                    .collect::<Vec<_>>(),
            );
            vmas.push(addr + *PAGE_SIZE);
        }

        if shuffle {
            let mut rng = thread_rng();
            pages.shuffle(&mut rng);
        }

        let chunk_size = pages.len() / nr_threads;
        for i in 0..loops {
            start_tracing(&threads, i == 0);

            pages
                .chunks(chunk_size)
                .zip(txs.iter())
                .for_each(|(chunk, tx)| {
                    tx.send(Arc::new(chunk)).unwrap();
                });

            for _ in 0..nr_threads {
                rid.recv().unwrap();
            }

            if flush {
                vmas.iter().for_each(|addr| drop_vma(*addr, vma_size));
            }

            stop_tracing(&threads);

            if !flush {
                vmas.iter().for_each(|addr| drop_vma(*addr, vma_size));
            }
        }
    });
}
