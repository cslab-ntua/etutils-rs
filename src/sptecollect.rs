use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

const BUFSIZ: usize = 1 << 12;
const PTE_CONT: u64 = 1 << 52;

struct SpteStats {
    ptes: u64,
    pmds: u64,
    contptes: u64,
    contpmds: u64,
}

fn main() {
    let sptdump = env::args().nth(1).unwrap();
    let out = env::args().nth(2).unwrap();
    let reader = BufReader::with_capacity(BUFSIZ, File::open(&sptdump).unwrap());
    let mut writer = BufWriter::new(File::create(&out).unwrap());

    let mut stats = SpteStats {
        ptes: 0,
        pmds: 0,
        contptes: 0,
        contpmds: 0,
    };

    for line in reader.lines() {
        let line = line.unwrap();
        let mut spte = line.splitn(3, ',');

        let gfn = u64::from_str_radix(
            spte.next()
                .unwrap()
                .split_once('=')
                .unwrap()
                .1
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap();
        let pte = u64::from_str_radix(
            spte.next()
                .unwrap()
                .split_once('=')
                .unwrap()
                .1
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap();
        let level: u8 = spte
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .parse()
            .unwrap();

        if pte == 0 {
            continue;
        }

        let contig = (pte & PTE_CONT) != 0;
        if contig {
            write!(
                writer,
                "gfn=0x{:x}, pte=0x{:x}, level={}\n",
                gfn, pte, level
            )
            .unwrap();
        }

        if level == 2 {
            stats.pmds += 1;
            if contig {
                stats.contpmds += 1;
            }
        } else if level == 3 {
            stats.ptes += 1;
            if contig {
                stats.contptes += 1;
            }
        }
    }

    if stats.ptes != 0 {
        println!(
            "Non-zero PTEs: {}, ContPTEs: {}, Coverage {:.2}%",
            stats.ptes,
            stats.contptes,
            100.0 * stats.contptes as f64 / stats.ptes as f64
        );
    }
    if stats.pmds != 0 {
        println!(
            "Non-zero PMDs: {}, ContPMDs: {}, Coverage {:.2}%",
            stats.pmds,
            stats.contpmds,
            100.0 * stats.contpmds as f64 / stats.pmds as f64
        );
    }
}
