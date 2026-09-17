//! aws-lc-rs 1.16.2 (nearcore 2.14 pin, mldsa-native b61e84f0) side of the differential fuzz.
#[path = "../../mldsa-diff/src/cases.rs"]
mod cases;

use aws_lc_rs::encoding::{AsRawBytes, PqdsaPrivateKeyRaw};
use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair};
use near_mldsa_native_sys as nx;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = &args[1];
    let n: u64 = args[2].parse().unwrap();
    let seed: u64 = args[3].parse().unwrap();
    let threads: usize = args[4].parse().unwrap();
    let pool = cases::load_pool(&format!("{out_dir}/pool.bin"));

    // Keygen/sign cross-check: aws-lc-rs 1.16.2 vs mldsa-native 834a90d.
    let mut r = cases::Rng(116);
    let mut ok = 0;
    for _ in 0..2000 {
        let mut seed32 = [0u8; 32];
        r.fill(&mut seed32);
        let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed32).unwrap();
        let raw: PqdsaPrivateKeyRaw<'static> = kp.private_key().as_raw_bytes().unwrap();
        let (mut pk, mut sk) = ([0u8; 1952], [0u8; 4032]);
        nx::keypair_from_seed(&seed32, &mut pk, &mut sk).unwrap();
        assert_eq!(kp.public_key().as_ref(), &pk[..]);
        assert_eq!(raw.as_ref(), &sk[..]);
        let mut msg = vec![0u8; (r.next() % 2000) as usize];
        r.fill(&mut msg);
        let mut sig = [0u8; 3309];
        kp.sign(&msg, &mut sig).unwrap();
        assert!(nx::verify(&pk, &msg, &sig));
        let mut nsig = [0u8; 3309];
        let mut rnd = [0u8; 32];
        r.fill(&mut rnd);
        nx::sign(&sk, &msg, &rnd, &mut nsig).unwrap();
        assert!(UnparsedPublicKey::new(&ML_DSA_65, &pk[..]).verify(&msg, &nsig).is_ok());
        let kp2 = PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, &sk).unwrap();
        assert_eq!(kp2.public_key().as_ref(), &pk[..]);
        ok += 1;
    }
    eprintln!("aws116 cross-check: {ok} seeds keygen byte-identical, sign/verify both directions ok");

    let results = vec![0u8; n as usize];
    let chunk = (n as usize).div_ceil(threads);
    let t0 = std::time::Instant::now();
    std::thread::scope(|s| {
        for (ci, res) in results.chunks(chunk).enumerate() {
            let pool = &pool;
            // SAFETY: disjoint chunks, one writer each.
            let res = unsafe { std::slice::from_raw_parts_mut(res.as_ptr() as *mut u8, res.len()) };
            s.spawn(move || {
                for (off, rv) in res.iter_mut().enumerate() {
                    let idx = (ci * chunk + off) as u64;
                    let (_label, pk, msg, sig) = cases::make_case(pool, seed, idx);
                    *rv = UnparsedPublicKey::new(&ML_DSA_65, &pk[..]).verify(&msg, &sig[..]).is_ok() as u8;
                }
            });
        }
    });
    std::fs::write(format!("{out_dir}/results116.bin"), &results).unwrap();
    let r118 = std::fs::read(format!("{out_dir}/results118.bin")).unwrap();
    let labels = std::fs::read(format!("{out_dir}/labels.bin")).unwrap();
    let mut mism = 0u64;
    let mut accepted = 0u64;
    for i in 0..n as usize {
        let a116 = results[i] == 1;
        accepted += a116 as u64;
        let a118 = r118[i] & 1 == 1;
        if a116 != a118 || (r118[i] != 0 && r118[i] != 0b1111) {
            mism += 1;
            if mism <= 20 {
                eprintln!("MISMATCH case {i} label {} aws116={a116} bits118={:04b}", cases::LABELS[labels[i] as usize], r118[i]);
            }
        }
    }
    println!("aws116 cases={n} seed={seed} secs={:.1} accepted={accepted} mismatches_vs_all_others={mism}", t0.elapsed().as_secs_f64());
}
