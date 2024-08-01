use std::io::Read;
use vsock::VsockStream;

const VSOCK_CID: u32 = 9999;
const VSOCK_PORT: u32 = 9999;

fn main() {
    eprintln!("Connecting to the VM...");
    let mut stream = VsockStream::connect_with_cid_port(VSOCK_CID, VSOCK_PORT).unwrap();

    let mut buf = vec![];
    eprintln!("Reading pfns...");
    stream.read_to_end(&mut buf).unwrap();

    buf.chunks_exact(8).for_each(|x| {
        let mut pfn = u64::from_le_bytes(x.try_into().unwrap());
        let level = if pfn & (1u64 << 63) != 0 { 2 } else { 3 };
        pfn &= !(1u64 << 63);

        println!("pfn=0x{:x}, level={}", pfn, level);
    });
}
