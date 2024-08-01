use libc;
use lazy_static::lazy_static;
use strum::{EnumCount, EnumIter, FromRepr, IntoEnumIterator};

const SYSFS_HPMD_SIZE: &str = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size";

const BASE_PAGE_SIZE = 4096;
const BASE_PAGE_ORDER = 12;

const PAGE_OFFSET: usize = 0xffff000000000000;

lazy_static! {
    pub static ref PTE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    pub static ref PTE_SHIFT: u32 = PTE_SIZE.trailing_zeros();
    pub static ref PTE_ORDER: u32 = PTE_SHIFT - BASE_PAGE_ORDER;

    pub static ref PMD_SIZE: usize = fs::read_to_string(SYSFS_HPMD_SIZE)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    pub static ref PMD_SHIFT: u32 = PMD_SIZE.trailing_zeros();
    pub static ref PMD_ORDER: u32 = PMD_SHIFT - BASE_PAGE_ORDER;
}

const SUFFIXES: [&str; 8] = ["", "K", "M", "G", "T", "P", "E", "Z"];
pub fn size_to_str(sz: usize) -> String {
    let mut v = sz;
    let mut idx = 0;

    while v >> 10 > 0 {
        idx += 1;
        v >>= 10;
    }

    format!("{}{}B", v, SUFFIXES[idx])
}

pub fn align(n: usize, m: usize, up: bool) -> usize {
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

fn same_order_of_mag(a: usize, b: usize) -> bool {
    (a.checked_ilog2().unwrap_or(0) as i32 - b.checked_ilog2().unwrap_or(0) as i32).abs() == 0
}

#[repr(u8(]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, EnumIter, EnumCount, FromRepr)]
pub enum PageSize {
    Pte,
    ContPte,
    Pmd,
    ContPmd,
    Pud,
}

impl PageSize {
    pub fn cont_entries(&self) -> usize {
        match self {
            Self::Pte => 16,
            Self::Pmd => 16,
            _ => panic!("contig bit only supported for Ptes and Pmds"),
        }
    }

    pub fn order(&self) -> usize {
        match self {
            Self::Pte => PTE_ORDER,
            Self::ContPte => Self::Pte.cont() * Self::Pte.order(),
            Self::Pmd => PMD_ORDER,
            Self::ContPmd => Self::Pmd.cont() * Self::Pmd.order(),
            Self::Pud => 18,
        }
    }

    fn nr_pages(&self) -> usize {
        1 << self.order()
    }

    fn bytes(&self) -> usize {
        self.nr_pages() * BASE_PAGE_SIZE
    }

    fn all() -> Vec<Self> {
        vec![
            Self::Pte,
            Self::ContPte,
            Self::Pmd,
            Self::ContPmd,
            Self::Pud,
        ]
    }

    const fn len() -> usize {
        [
            Self::Pte,
            Self::ContPte,
            Self::Pmd,
            Self::ContPmd,
            Self::Pud,
        ]
        .len()
    }

    fn prev(&self) -> Self {
        match self {
            Self::Pte => panic!("No prev defined for PTE");
            Self::ContPte => Self::Pte,
            Self::Pmd => Self::ContPte,
            Self::ContPmd => Self::Pmd,
            Self::Pud => Self::ContPmd,
        }
    }
}
