use pagemap::{page_size, PageMap};
use std::io::Write;
use std::{env, fs, process, thread, time};
use vsock::{VsockListener, VMADDR_CID_ANY};

const SYSFS_HPMD_SIZE: &'static str = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size";
const VSOCK_PORT: u32 = 9999;
const BUFSIZ: usize = 8 << 20;

fn main() {
    let pid = env::args()
        .nth(1)
        .map_or_else(|| process::id() as u64, |v| v.parse().unwrap());

    let pgsz = page_size().unwrap();
    let pgshift = pgsz.trailing_zeros() as u64;

    let thpsz: u64 = fs::read_to_string(SYSFS_HPMD_SIZE)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    eprintln!("Listening on VSOCK...");
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, VSOCK_PORT).unwrap();
    let (mut stream, _) = listener.accept().unwrap();

    eprintln!("Incoming request accepted...");

    let mut pm = PageMap::new(pid).unwrap();
    let mut pfns = Vec::with_capacity(BUFSIZ);
    for mapping in pm.maps().unwrap().iter() {
        let vma = mapping.vma();
        let start = vma.start_address();
        let end = vma.last_address();

        let mut addr = start;
        while addr <= end {
            let vpn = addr >> pgshift;
            let entry = pm.pagemap_vpn(vpn).unwrap();

            let present = entry.present();
            if !present {
                addr += pgsz;
                continue;
            }

            let mut pfn = entry.pfn().unwrap();
            let thp = entry.thp().unwrap_or(false);

            addr += if thp { thpsz } else { pgsz };

            let zero = entry.zero_page().unwrap_or(false);
            let anon = entry.anon().unwrap_or(false);
            let mmap = entry.mmap().unwrap_or(false);

            if zero || (!anon && !mmap) {
                continue;
            }

            if thp {
                pfn |= 1u64 << 63;
            }
            pfns.extend(pfn.to_le_bytes());

            if pfns.len() >= BUFSIZ {
                eprintln!("Sending chunk...");
                stream.write_all(&pfns).unwrap();
                pfns.clear();
                thread::sleep(time::Duration::from_secs(5));
            }
        }
    }
    stream.write_all(&pfns).unwrap();
}
