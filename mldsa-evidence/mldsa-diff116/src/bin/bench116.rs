#[path = "../../../mldsa-diff/src/cases.rs"]
#[allow(dead_code)]
mod cases;
#[path = "../../../mldsa-diff/src/benchcommon.rs"]
mod benchcommon;
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::unstable::signature::{ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair};
use benchcommon::{NV, gen_vectors, time_op};
use near_mldsa_native_sys as nx;
use std::hint::black_box;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (op, n) = (args[2].as_str(), args[3].parse::<usize>().unwrap());
    let v = gen_vectors(
        |s, pk, sk| nx::keypair_from_seed(s, pk, sk).unwrap(),
        |sk, m, rnd, sig| nx::sign(sk, m, rnd, sig).unwrap(),
    );
    let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &v.seeds[0]).unwrap();
    let mut sig = [0u8; 3309];
    let us = match op {
        "keygen" => time_op(n, |i| { black_box(PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &v.seeds[i % NV]).unwrap()); }),
        "sign" => time_op(n, |i| { kp.sign(&v.msgs[i % NV], &mut sig).unwrap(); }),
        "verify" => time_op(n, |i| { assert!(UnparsedPublicKey::new(&ML_DSA_65, &v.pks[i % NV][..]).verify(&v.msgs[i % NV], &v.sigs[i % NV][..]).is_ok()); }),
        _ => panic!("op"),
    };
    println!("aws116 {op} {us:.2}");
}
