use mldsa_diff::skcases::{REGIONS, base_keys, make_sk};
use mldsa_diff::{nc, nx};

fn main() {
    let n: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
    let keys = base_keys();
    let threads = 16u64;
    let stats = std::sync::Mutex::new(vec![[0u64; 3]; 8]); // total, accepted, mismatches
    std::thread::scope(|s| {
        for t in 0..threads {
            let (keys, stats) = (&keys, &stats);
            s.spawn(move || {
                let mut local = vec![[0u64; 3]; 8];
                for idx in (0..n).filter(|i| i % threads == t) {
                    let (kind, sk) = make_sk(keys, idx);
                    let aws = awslc118::signature::PqdsaKeyPair::from_raw_private_key(
                        &awslc118::signature::ML_DSA_65_SIGNING, &sk[..]);
                    let (mut pk1, mut pk2) = ([0u8; 1952], [0u8; 1952]);
                    let a = aws.is_ok();
                    let x = nx::pk_from_sk(&sk, &mut pk1) == 0;
                    let c = nc::pk_from_sk(&sk, &mut pk2) == 0;
                    local[kind][0] += 1;
                    local[kind][1] += (a && x && c) as u64;
                    let mut mism = a != x || x != c;
                    if a && x && c {
                        use awslc118::signature::KeyPair;
                        let kp = aws.unwrap();
                        mism |= kp.public_key().as_ref() != &pk1[..] || pk1 != pk2;
                    }
                    if mism {
                        local[kind][2] += 1;
                        eprintln!("MISMATCH idx {idx} kind {kind} aws={a} nx={x} nc={c}");
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
        println!("sk118 {:>10} total={:>7} accepted_by_all={:>7} mismatches={}", names[k], g[k][0], g[k][1], g[k][2]);
    }
    let _ = REGIONS;
}
