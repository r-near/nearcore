//! Shared helpers: the verifiers/signers under comparison.
pub mod cases;
pub mod benchcommon;
pub mod skcases;
use core::ffi::c_int;

pub const PK: usize = 1952;
pub const SK: usize = 4032;
pub const SIG: usize = 3309;

macro_rules! variant {
    ($m:ident, $kp:ident, $sig:ident, $ver:ident, $pk:ident) => {
        pub mod $m {
            use super::*;
            unsafe extern "C" {
                fn $kp(pk: *mut u8, sk: *mut u8, seed: *const u8) -> c_int;
                fn $sig(sig: *mut u8, m: *const u8, mlen: usize, pre: *const u8, prelen: usize,
                        rnd: *const u8, sk: *const u8, externalmu: c_int) -> c_int;
                fn $ver(sig: *const u8, m: *const u8, mlen: usize, ctx: *const u8, ctxlen: usize,
                        pk: *const u8) -> c_int;
                fn $pk(pk: *mut u8, sk: *const u8) -> c_int;
            }
            pub fn keypair(seed: &[u8; 32], pk: &mut [u8; PK], sk: &mut [u8; SK]) -> c_int {
                unsafe { $kp(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) }
            }
            pub fn sign(sk: &[u8; SK], msg: &[u8], rnd: &[u8; 32], sig: &mut [u8; SIG]) -> c_int {
                let pre = [0u8, 0u8];
                unsafe { $sig(sig.as_mut_ptr(), msg.as_ptr(), msg.len(), pre.as_ptr(), 2, rnd.as_ptr(), sk.as_ptr(), 0) }
            }
            pub fn verify(pk: &[u8; PK], msg: &[u8], sig: &[u8; SIG]) -> bool {
                unsafe { $ver(sig.as_ptr(), msg.as_ptr(), msg.len(), core::ptr::null(), 0, pk.as_ptr()) == 0 }
            }
            pub fn pk_from_sk(sk: &[u8; SK], pk: &mut [u8; PK]) -> c_int {
                unsafe { $pk(pk.as_mut_ptr(), sk.as_ptr()) }
            }
        }
    };
}
// Prototype sys crate build: native AVX2 arith + AVX2 Keccak x4, runtime dispatch.
variant!(nx, mldsa65_keypair_internal, mldsa65_signature_internal, mldsa65_verify, mldsa65_pk_from_sk);
// Native AVX2 arith, C Keccak.
variant!(na, mldsa65a_keypair_internal, mldsa65a_signature_internal, mldsa65a_verify, mldsa65a_pk_from_sk);
// Portable C.
variant!(nc, mldsa65c_keypair_internal, mldsa65c_signature_internal, mldsa65c_verify, mldsa65c_pk_from_sk);

// Make sure the sys crate (and its AVX2 detection symbol) is linked.
pub use near_mldsa_native_sys as _sys;

pub mod aws118 {
    use awslc118::signature::{KeyPair, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey};
    pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&ML_DSA_65, pk).verify(msg, sig).is_ok()
    }
    pub fn keypair_from_seed(seed: &[u8; 32]) -> PqdsaKeyPair {
        PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed).unwrap()
    }
    pub fn sign(kp: &PqdsaKeyPair, msg: &[u8], out: &mut [u8]) {
        kp.sign(msg, out).unwrap();
    }
    pub fn public_key(kp: &PqdsaKeyPair) -> Vec<u8> {
        kp.public_key().as_ref().to_vec()
    }
}

/// SplitMix64, for reproducible case generation.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 { self.next() % n }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}
