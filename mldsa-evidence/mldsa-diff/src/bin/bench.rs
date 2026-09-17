use mldsa_diff::benchcommon::{NV, gen_vectors, time_op};
use mldsa_diff::{aws118, na, nc, nx};
use std::hint::black_box;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (imp, op, n) = (args[1].as_str(), args[2].as_str(), args[3].parse::<usize>().unwrap());
    let v = gen_vectors(
        |s, pk, sk| assert_eq!(nx::keypair(s, pk, sk), 0),
        |sk, m, rnd, sig| assert_eq!(nx::sign(sk, m, rnd, sig), 0),
    );
    let (mut pk0, mut sk0) = ([0u8; 1952], [0u8; 4032]);
    nc::keypair(&v.seeds[0], &mut pk0, &mut sk0);
    let aws_kp = aws118::keypair_from_seed(&v.seeds[0]);
    let mut sig = [0u8; 3309];
    let imp = if imp == "aws118noavx2" { "aws118" } else { imp };
    let us = match (imp, op) {
        ("aws118", "keygen") => time_op(n, |i| { black_box(aws118::keypair_from_seed(&v.seeds[i % NV])); }),
        ("aws118", "sign") => time_op(n, |i| aws118::sign(&aws_kp, &v.msgs[i % NV], &mut sig[..])),
        ("aws118", "verify") => time_op(n, |i| { assert!(aws118::verify(&v.pks[i % NV][..], &v.msgs[i % NV], &v.sigs[i % NV][..])); }),
        (imp, op) => {
            let (kp, sg, vf): (fn(&[u8; 32], &mut [u8; 1952], &mut [u8; 4032]) -> i32,
                               fn(&[u8; 4032], &[u8], &[u8; 32], &mut [u8; 3309]) -> i32,
                               fn(&[u8; 1952], &[u8], &[u8; 3309]) -> bool) = match imp {
                "nx" => (nx::keypair, nx::sign, nx::verify),
                "na" => (na::keypair, na::sign, na::verify),
                "nc" => (nc::keypair, nc::sign, nc::verify),
                _ => panic!("impl"),
            };
            let (mut pk, mut sk) = ([0u8; 1952], [0u8; 4032]);
            match op {
                "keygen" => time_op(n, |i| { kp(&v.seeds[i % NV], &mut pk, &mut sk); }),
                "sign" => time_op(n, |i| { sg(&sk0, &v.msgs[i % NV], &v.rnds[i % NV], &mut sig); }),
                "verify" => time_op(n, |i| { assert!(vf(&v.pks[i % NV], &v.msgs[i % NV], &v.sigs[i % NV])); }),
                _ => panic!("op"),
            }
        }
    };
    println!("{} {op} {us:.2}", args[1]);
}
