/// usage: ./idle <pid>
///
/// Uses Linux idle page tracking to detect accessed pages and estimate working set size.
use pagemap::PageMap;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use std::{env, fs, path, process, thread, time};

const SYSFS_IDLE_BITMAP: &str = "/sys/kernel/mm/page_idle/bitmap";

fn print_map(map: &HashMap<u64, u64>) {
    let mut result = map.iter().collect::<Vec<_>>();
    result.sort_by_key(|x| x.1);

    for (k, v) in result.iter() {
        println!("0x{:x} -> {}", k, v);
    }

    let set = map
        .values()
        .filter_map(|&x| if x > 0 { Some(x) } else { None })
        .count();

    println!(
        "WSS: {:.2}, {:.2}%",
        (set * 4096) as f64 / 1024.0 / 1024.0,
        100.0 * (set as f64 / map.len() as f64)
    );
}

fn main() {
    let pid = env::args()
        .nth(1)
        .map_or_else(|| process::id() as u64, |v| v.parse().unwrap());
    let procfs_path = path::PathBuf::from(format!("/proc/{}", pid));

    let accessed: Arc<Mutex<HashMap<u64, u64>>> = Arc::new(Mutex::new(HashMap::new()));

    let binding = accessed.clone();
    ctrlc::set_handler(move || {
        let accessed = binding.lock().unwrap();
        print_map(&accessed);
        process::exit(0);
    })
    .unwrap();

    let mut read_idle = false;

    loop {
        if !procfs_path.exists() {
            break;
        }

        let mut seen = HashMap::new();

        let mut pagemap = PageMap::new(pid).unwrap();
        for mapping in pagemap.maps().unwrap().iter() {
            if !procfs_path.exists() {
                break;
            }

            let vma = mapping.vma();
            let start = vma.start_address();
            let end = vma.last_address();

            let mut addr = start;
            while addr <= end {
                let vpn = addr >> 12;

                let entry = pagemap.pagemap_vpn(vpn);
                if entry.is_err() {
                    println!("Error processing VPN 0x{:x}", vpn);
                    addr += 4096;
                    continue;
                }

                let entry = entry.unwrap();
                if !entry.present()
                    || !(entry.anon().unwrap_or(false) || entry.mmap().unwrap_or(false))
                {
                    addr += 4096;
                    continue;
                }

                let pfn = entry.pfn().unwrap();
                let idx = (pfn / 64) * 8;

                if !read_idle && !seen.contains_key(&idx) {
                    let mut idlemap = fs::OpenOptions::new()
                        .write(true)
                        .open(SYSFS_IDLE_BITMAP)
                        .unwrap();

                    if idlemap.seek(SeekFrom::Start(idx)).is_err() {
                        addr += 4096;
                        continue;
                    }

                    let idlebits: [u8; 8] = [0xff; 8];
                    let _n = idlemap.write(&idlebits).unwrap();

                    seen.entry(idx).or_insert([0; 8]);
                } else if read_idle {
                    let idle;
                    if seen.contains_key(&idx) {
                        let idlebits = seen[&idx];
                        idle = (idlebits[((pfn % 64) / 8) as usize] & (1 << ((pfn % 64) % 8))) != 0;
                    } else {
                        let mut idlemap = fs::OpenOptions::new()
                            .read(true)
                            .open(SYSFS_IDLE_BITMAP)
                            .unwrap();
                        if idlemap.seek(SeekFrom::Start(idx)).is_err() {
                            addr += 4096;
                            continue;
                        }
                        let mut idlebits: [u8; 8] = [0; 8];
                        let _n = idlemap.read(&mut idlebits).unwrap();
                        idle = (idlebits[((pfn % 64) / 8) as usize] & (1 << ((pfn % 64) % 8))) != 0;
                        seen.entry(idx).or_insert(idlebits);
                    }
                    let mut accessed = accessed.lock().unwrap();
                    accessed.entry(vpn).or_insert(0);
                    if !idle {
                        accessed.entry(vpn).and_modify(|x| *x += 1);
                    }
                }
                addr += 4096;
            }
        }

        if !read_idle {
            thread::sleep(time::Duration::from_secs(5));
        } else {
            let accessed = accessed.lock().unwrap();
            println!(
                "total: {}, nonzero: {}, max {}",
                accessed.len(),
                accessed.clone().into_values().filter(|&v| v > 0).count(),
                accessed.values().max().unwrap_or(&0)
            );
        }

        read_idle = !read_idle;
    }

    let accessed = accessed.lock().unwrap();
    print_map(&accessed);
}
