use std::env;
use std::fs::File;
use std::io::{self, BufRead};

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

fn main() {
    let hints = env::args().nth(1).unwrap();
    let misses = env::args().nth(2).unwrap();

    let ranges = io::BufReader::new(File::open(hints).unwrap())
        .lines()
        .map(|line| {
            let line = line.unwrap();
            let (address, order) = line.trim().split_once(' ').unwrap();
            let start = usize::from_str_radix(address.trim(), 16).unwrap();
            start..(start + (1 << order.trim().parse::<usize>().unwrap()))
        })
        .collect::<Vec<_>>();

    let gaps = ranges
        .windows(2)
        .map(|x| x[1].start - x[0].end)
        .collect::<Vec<_>>();

    let misses = io::BufReader::new(File::open(misses).unwrap())
        .lines()
        .map(|line| {
            let line = line.unwrap();
            usize::from_str_radix(line.trim(), 16).unwrap()
        })
        .collect::<Vec<_>>();

    if env::var("DRYRUN")
        .unwrap_or("false".to_owned())
        .parse::<bool>()
        .unwrap()
    {
        ranges.iter().zip(gaps).for_each(|(range, gap)| {
            print!(
                "0x{:x}-0x{:x} ({})",
                range.start,
                range.end,
                size_to_str((range.end - range.start) << 12)
            );
            let mc: usize = misses
                .iter()
                .filter(|address| range.contains(&(*address >> 12)))
                .count();
            println!(" misses = {}", mc);
            if gap > 0 {
                if gap < 512 {
                    print!("SMALLGAP!!! ");
                }
                print!("({})", size_to_str(gap << 12));
                let mc: usize = misses
                    .iter()
                    .filter(|address| (range.end..range.end + gap).contains(&(*address >> 12)))
                    .count();
                println!(" misses = {}", mc);
            }
        });
        return;
    }

    ranges.iter().zip(gaps).for_each(|(range, gap)| {
        println!("0x{:x}-0x{:x}", range.start << 12, range.end << 12);
        if gap > 0 && gap <= 16 * 512 {
            let mut next = range.end;
            if next & ((1 << 9) - 1) != 0 {
                next += 512;
                next &= !((1 << 9) - 1);
            }
            while next + 512 <= range.end + gap {
                println!("0x{:x}-0x{:x}", next << 12, (next + 512) << 12);
                next += 512;
            }
        }
    });
}
