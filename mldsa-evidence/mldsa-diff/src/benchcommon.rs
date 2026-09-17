//! Shared benchmark driver. Each process run measures one (impl, op) pair so
//! a shell loop can interleave implementations, including aws-lc-rs 1.16.2
//! which has to live in a separate binary.
use std::hint::black_box;
use std::time::Instant;

pub struct Vectors {
    pub seeds: Vec<[u8; 32]>,
    pub rnds: Vec<[u8; 32]>,
    pub msgs: Vec<Vec<u8>>,
    pub pks: Vec<Box<[u8; 1952]>>,
    pub sigs: Vec<Box<[u8; 3309]>>,
}

pub const NV: usize = 1024;

pub fn gen_vectors(
    keypair: impl Fn(&[u8; 32], &mut [u8; 1952], &mut [u8; 4032]),
    sign: impl Fn(&[u8; 4032], &[u8], &[u8; 32], &mut [u8; 3309]),
) -> Vectors {
    let mut r = crate::cases::Rng(0xBE5C);
    let mut v = Vectors { seeds: vec![], rnds: vec![], msgs: vec![], pks: vec![], sigs: vec![] };
    let mut keys = vec![];
    for _ in 0..16 {
        let mut seed = [0u8; 32];
        r.fill(&mut seed);
        let (mut pk, mut sk) = (Box::new([0u8; 1952]), Box::new([0u8; 4032]));
        keypair(&seed, &mut pk, &mut sk);
        keys.push((pk, sk));
    }
    for i in 0..NV {
        let mut seed = [0u8; 32];
        r.fill(&mut seed);
        let mut rnd = [0u8; 32];
        r.fill(&mut rnd);
        let mut msg = vec![0u8; 32];
        r.fill(&mut msg);
        let (pk, sk) = &keys[i % 16];
        let mut sig = Box::new([0u8; 3309]);
        sign(sk, &msg, &[0u8; 32], &mut sig);
        v.seeds.push(seed);
        v.rnds.push(rnd);
        v.msgs.push(msg);
        v.pks.push(pk.clone());
        v.sigs.push(sig);
    }
    v
}

/// Runs `op` over `n` iterations after a warmup and returns microseconds per op.
pub fn time_op(n: usize, mut op: impl FnMut(usize)) -> f64 {
    for i in 0..(n / 10).max(20) {
        op(black_box(i));
    }
    let t = Instant::now();
    for i in 0..n {
        op(black_box(i));
    }
    t.elapsed().as_secs_f64() * 1e6 / n as f64
}
