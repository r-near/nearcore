#[path = "../../../mldsa-diff/src/cases.rs"]
#[allow(dead_code)]
mod cases;
#[path = "../../../mldsa-diff/src/skcases.rs"]
mod skcases;
use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::unstable::signature::{ML_DSA_65_SIGNING, PqdsaKeyPair};

fn main() {
    let n: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
    let keys = skcases::base_keys();
    let threads = 16u64;
    let stats = std::sync::Mutex::new(vec![[0u64; 3]; 8]);
    std::thread::scope(|s| {
        for t in 0..threads {
            let (keys, stats) = (&keys, &stats);
            s.spawn(move || {
                let mut local = vec![[0u64; 3]; 8];
                for idx in (0..n).filter(|i| i % threads == t) {
                    let (kind, sk) = skcases::make_sk(keys, idx);
                    let aws = PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, &sk[..]);
                    let mut pk = [0u8; 1952];
                    let x = near_mldsa_native_sys::public_key_from_secret_key(&sk, &mut pk).is_ok();
                    let a = aws.is_ok();
                    local[kind][0] += 1;
                    local[kind][1] += (a && x) as u64;
                    let mism = a != x || (a && x && aws.unwrap().public_key().as_ref() != &pk[..]);
                    if mism {
                        local[kind][2] += 1;
                        eprintln!("MISMATCH idx {idx} kind {kind} aws116={a} nx={x}");
                    }
                }
                let mut g = stats.lock().unwrap();
                for k in 0..8 { for j in 0..3 { g[k][j] += local[k][j]; } }
            });
        }
    });
    let g = stats.into_inner().unwrap();
    let names = ["rho", "key", "tr", "s1", "s2", "t0", "unmodified", "random"];
    for k in 0..8 {
        println!("sk116 {:>10} total={:>7} accepted_by_all={:>7} mismatches={}", names[k], g[k][0], g[k][1], g[k][2]);
    }
}
