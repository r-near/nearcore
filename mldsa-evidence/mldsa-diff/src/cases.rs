//! Reproducible malformed-input generation shared by the aws-lc-rs 1.18.1 and
//! 1.16.2 harness binaries (1.16.2 lives in a separate crate because Cargo
//! refuses two semver-compatible aws-lc-rs versions in one graph).
use std::io::{Read, Write};

pub const PK: usize = 1952;
pub const SIG: usize = 3309;
const CTILDE: usize = 48;
const Z_OFF: usize = 48;
const Z_POLY_BYTES: usize = 640;
const L: usize = 5;
const H_OFF: usize = 3248;
const OMEGA: usize = 55;
const K: usize = 6;

pub struct Base {
    pub pk: Box<[u8; PK]>,
    pub msg: Vec<u8>,
    pub sig: Box<[u8; SIG]>,
}

pub fn save_pool(path: &str, pool: &[Base]) {
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    f.write_all(&(pool.len() as u64).to_le_bytes()).unwrap();
    for b in pool {
        f.write_all(&b.pk[..]).unwrap();
        f.write_all(&(b.msg.len() as u64).to_le_bytes()).unwrap();
        f.write_all(&b.msg).unwrap();
        f.write_all(&b.sig[..]).unwrap();
    }
}

pub fn load_pool(path: &str) -> Vec<Base> {
    let mut f = std::io::BufReader::new(std::fs::File::open(path).unwrap());
    let mut n = [0u8; 8];
    f.read_exact(&mut n).unwrap();
    (0..u64::from_le_bytes(n))
        .map(|_| {
            let mut pk = Box::new([0u8; PK]);
            f.read_exact(&mut pk[..]).unwrap();
            let mut len = [0u8; 8];
            f.read_exact(&mut len).unwrap();
            let mut msg = vec![0u8; u64::from_le_bytes(len) as usize];
            f.read_exact(&mut msg).unwrap();
            let mut sig = Box::new([0u8; SIG]);
            f.read_exact(&mut sig[..]).unwrap();
            Base { pk, msg, sig }
        })
        .collect()
}

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

pub const LABELS: &[&str] = &[
    "valid",
    "sig_bitflip",
    "ctilde_byte",
    "z_byte",
    "hint_byte",
    "hint_counts_decreasing",
    "hint_count_gt_omega",
    "hint_duplicate_index",
    "hint_swap_order",
    "hint_nonzero_padding",
    "hint_move_between_rows",
    "hint_remove",
    "hint_add",
    "z_boundary",
    "z_boundary_plus_hint",
    "pk_bitflip",
    "pk_rho_byte",
    "msg_modified",
    "all_random",
    "other_pk",
    "sig_all_zero_or_ff",
    "ctilde_splice",
    "hints_cleared",
    "z_boundary_valid_range",
];

fn counts(sig: &[u8; SIG]) -> [usize; K] {
    let mut c = [0usize; K];
    for i in 0..K {
        c[i] = sig[H_OFF + OMEGA + i] as usize;
    }
    c
}

fn set_z(sig: &mut [u8; SIG], poly: usize, coeff: usize, enc: u32) {
    let bit = (Z_OFF + poly * Z_POLY_BYTES) * 8 + coeff * 20;
    for b in 0..20 {
        let byte = (bit + b) / 8;
        let off = (bit + b) % 8;
        if (enc >> b) & 1 == 1 {
            sig[byte] |= 1 << off;
        } else {
            sig[byte] &= !(1 << off);
        }
    }
}

const Z_BOUNDARY: &[u32] = &[
    0, 1, 195, 196, 197, 198, 524287, 524288, 524289, 1048378, 1048379, 1048380, 1048381, 1048575,
];

/// Builds case `idx` from the pool. Returns (label, pk, msg, sig).
pub fn make_case(
    pool: &[Base],
    seed: u64,
    idx: u64,
) -> (u8, Box<[u8; PK]>, std::borrow::Cow<'_, [u8]>, Box<[u8; SIG]>) {
    use std::borrow::Cow;
    let mut r = Rng(seed ^ idx.wrapping_mul(0xD1B54A32D192ED03));
    r.next();
    let b = &pool[r.below(pool.len() as u64) as usize];
    let mut pk = b.pk.clone();
    let mut sig = b.sig.clone();
    let mut msg: Cow<[u8]> = Cow::Borrowed(&b.msg);
    let label = r.below(LABELS.len() as u64) as u8;
    match label {
        0 => {}
        1 => {
            let p = r.below((SIG * 8) as u64) as usize;
            sig[p / 8] ^= 1 << (p % 8);
        }
        2 => sig[r.below(CTILDE as u64) as usize] = r.next() as u8,
        3 => sig[Z_OFF + r.below((L * Z_POLY_BYTES) as u64) as usize] = r.next() as u8,
        4 => sig[H_OFF + r.below((OMEGA + K) as u64) as usize] = r.next() as u8,
        5 => {
            let c = counts(&sig);
            let i = 1 + r.below((K - 1) as u64) as usize;
            if c[i - 1] > 0 {
                sig[H_OFF + OMEGA + i] = (c[i - 1] - 1 - r.below(c[i - 1] as u64) as usize) as u8;
            } else {
                sig[H_OFF + OMEGA + i - 1] = 1 + r.below(OMEGA as u64) as u8;
                sig[H_OFF + OMEGA + i] = 0;
            }
        }
        6 => {
            let i = r.below(K as u64) as usize;
            sig[H_OFF + OMEGA + i] = (OMEGA + 1 + r.below((255 - OMEGA) as u64) as usize) as u8;
        }
        7 | 8 => {
            let c = counts(&sig);
            let mut start = 0;
            let mut cands = vec![];
            for i in 0..K {
                for j in start + 1..c[i].max(start) {
                    cands.push(j);
                }
                start = c[i].max(start);
            }
            if let Some(&j) = cands.get(r.below(cands.len().max(1) as u64) as usize) {
                if label == 7 {
                    sig[H_OFF + j] = sig[H_OFF + j - 1];
                } else {
                    sig.swap(H_OFF + j, H_OFF + j - 1);
                }
            } else {
                sig[H_OFF] = sig[H_OFF].wrapping_add(1);
            }
        }
        9 => {
            let total = counts(&sig)[K - 1].min(OMEGA);
            if total < OMEGA {
                let j = total + r.below((OMEGA - total) as u64) as usize;
                sig[H_OFF + j] = 1 + r.below(255) as u8;
            } else {
                sig[H_OFF + OMEGA + K - 1] = (OMEGA - 1) as u8;
            }
        }
        10 => {
            let i = r.below((K - 1) as u64) as usize;
            let c = counts(&sig);
            if r.next() & 1 == 0 && c[i] > 0 && (i == 0 || c[i] > c[i - 1]) {
                sig[H_OFF + OMEGA + i] -= 1;
            } else if c[i] < c[i + 1] {
                sig[H_OFF + OMEGA + i] += 1;
            }
        }
        11 => {
            let c = counts(&sig);
            let total = c[K - 1].min(OMEGA);
            if total > 0 {
                let j = r.below(total as u64) as usize;
                for t in j..OMEGA - 1 {
                    sig[H_OFF + t] = sig[H_OFF + t + 1];
                }
                sig[H_OFF + OMEGA - 1] = 0;
                for i in 0..K {
                    if c[i] > j {
                        sig[H_OFF + OMEGA + i] -= 1;
                    }
                }
            }
        }
        12 => {
            let c = counts(&sig);
            let total = c[K - 1].min(OMEGA);
            if total < OMEGA {
                let row = r.below(K as u64) as usize;
                let lo = if row == 0 { 0 } else { c[row - 1] };
                let hi = c[row];
                let mut row_idx: Vec<u8> = sig[H_OFF + lo..H_OFF + hi].to_vec();
                let v = r.below(256) as u8;
                if !row_idx.contains(&v) {
                    row_idx.push(v);
                    row_idx.sort();
                    let tail: Vec<u8> = sig[H_OFF + hi..H_OFF + total].to_vec();
                    let mut new = sig[H_OFF..H_OFF + lo].to_vec();
                    new.extend_from_slice(&row_idx);
                    new.extend_from_slice(&tail);
                    sig[H_OFF..H_OFF + new.len()].copy_from_slice(&new);
                    for i in row..K {
                        sig[H_OFF + OMEGA + i] += 1;
                    }
                }
            }
        }
        13 | 14 | 23 => {
            let enc = if label == 23 {
                197 + r.below((1048379 - 197 + 1) as u64) as u32
            } else {
                Z_BOUNDARY[r.below(Z_BOUNDARY.len() as u64) as usize]
            };
            set_z(&mut sig, r.below(L as u64) as usize, r.below(256) as usize, enc);
            if label == 14 {
                sig[H_OFF + OMEGA + r.below(K as u64) as usize] = 255;
            }
        }
        15 => {
            let p = r.below((PK * 8) as u64) as usize;
            pk[p / 8] ^= 1 << (p % 8);
        }
        16 => pk[r.below(32) as usize] = r.next() as u8,
        17 => {
            let mut m = b.msg.clone();
            match r.below(3) {
                0 if !m.is_empty() => {
                    let p = r.below((m.len() * 8) as u64) as usize;
                    m[p / 8] ^= 1 << (p % 8);
                }
                1 if !m.is_empty() => {
                    m.pop();
                }
                _ => m.push(r.next() as u8),
            }
            msg = Cow::Owned(m);
        }
        18 => {
            r.fill(&mut pk[..]);
            r.fill(&mut sig[..]);
        }
        19 => pk = pool[r.below(pool.len() as u64) as usize].pk.clone(),
        20 => sig.fill(if r.next() & 1 == 0 { 0 } else { 0xFF }),
        21 => {
            let o = &pool[r.below(pool.len() as u64) as usize];
            sig[..CTILDE].copy_from_slice(&o.sig[..CTILDE]);
        }
        22 => sig[H_OFF..].fill(0),
        _ => unreachable!(),
    }
    (label, pk, msg, sig)
}
