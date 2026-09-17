//! Secret-key validation differential: the check near-crypto's `FromStr for SecretKey`
//! and `sign`/`public_key` rely on (aws-lc-rs `from_raw_private_key` vs mldsa-native `pk_from_sk`).
use crate::cases::Rng;

pub const REGIONS: &[(&str, usize, usize)] = &[
    ("rho", 0, 32),
    ("key", 32, 64),
    ("tr", 64, 128),
    ("s1", 128, 768),
    ("s2", 768, 1536),
    ("t0", 1536, 4032),
];

pub fn base_keys() -> Vec<([u8; 32], Box<[u8; 4032]>, Box<[u8; 1952]>)> {
    let mut r = Rng(0x5CA1AB1E);
    (0..64)
        .map(|_| {
            let mut seed = [0u8; 32];
            r.fill(&mut seed);
            let (mut pk, mut sk) = (Box::new([0u8; 1952]), Box::new([0u8; 4032]));
            near_mldsa_native_sys::keypair_from_seed(&seed, &mut pk, &mut sk).unwrap();
            (seed, sk, pk)
        })
        .collect()
}

/// Returns (region index or 6 = unmodified / 7 = random sk, mutated sk).
pub fn make_sk(keys: &[([u8; 32], Box<[u8; 4032]>, Box<[u8; 1952]>)], idx: u64) -> (usize, Box<[u8; 4032]>) {
    let mut r = Rng(0xABCD ^ idx.wrapping_mul(0x9E3779B97F4A7C15));
    r.next();
    let mut sk = keys[r.below(keys.len() as u64) as usize].1.clone();
    let kind = r.below(8) as usize;
    match kind {
        0..=5 => {
            let (_, lo, hi) = REGIONS[kind];
            if r.next() & 1 == 0 {
                let p = lo * 8 + r.below(((hi - lo) * 8) as u64) as usize;
                sk[p / 8] ^= 1 << (p % 8);
            } else {
                sk[lo + r.below((hi - lo) as u64) as usize] = r.next() as u8;
            }
        }
        6 => {}
        _ => r.fill(&mut sk[..]),
    }
    (kind, sk)
}
