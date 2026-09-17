use mldsa_diff::cases::{self, Base, LABELS};
use mldsa_diff::{aws118, na, nc, nx};
use std::sync::atomic::{AtomicU64, Ordering};

fn build_pool() -> Vec<Base> {
    let mut r = cases::Rng(0x5eed);
    let lens = [0usize, 1, 13, 32, 64, 255, 256, 1000, 4096, 65536];
    let mut pool = vec![];
    for k in 0..64u64 {
        let mut seed = [0u8; 32];
        r.fill(&mut seed);
        let kp = aws118::keypair_from_seed(&seed);
        let pk_vec = aws118::public_key(&kp);
        let mut sk = [0u8; 4032];
        let mut pk = Box::new([0u8; 1952]);
        nx::keypair(&seed, &mut pk, &mut sk);
        assert_eq!(&pk[..], &pk_vec[..]);
        for s in 0..24u64 {
            let len = if k < 4 && s == 0 { 1 << 20 } else { lens[r.below(lens.len() as u64) as usize] };
            let mut msg = vec![0u8; len];
            r.fill(&mut msg);
            let mut sig = Box::new([0u8; 3309]);
            match s % 3 {
                0 => aws118::sign(&kp, &msg, &mut sig[..]),
                1 => assert_eq!(nx::sign(&sk, &msg, &[0u8; 32], &mut sig), 0),
                _ => {
                    let mut rnd = [0u8; 32];
                    r.fill(&mut rnd);
                    assert_eq!(nc::sign(&sk, &msg, &rnd, &mut sig), 0);
                }
            }
            pool.push(Base { pk: pk.clone(), msg, sig });
        }
    }
    pool
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = &args[1];
    let n: u64 = args[2].parse().unwrap();
    let seed: u64 = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(1);
    let threads: usize = args.get(4).map(|s| s.parse().unwrap()).unwrap_or(48);
    let pool_path = format!("{out_dir}/pool.bin");
    let pool = if std::path::Path::new(&pool_path).exists() {
        cases::load_pool(&pool_path)
    } else {
        let p = build_pool();
        cases::save_pool(&pool_path, &p);
        p
    };
    eprintln!("pool: {} base signatures; avx2 detected: {}", pool.len(), std::arch::is_x86_feature_detected!("avx2"));

    // Wrong-length and DER-SPKI checks against aws-lc-rs 1.18.1 (mldsa-native takes fixed arrays).
    {
        let b = &pool[1];
        let spki_hdr: [u8; 22] = [
            0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
        ];
        let mut spki = spki_hdr.to_vec();
        spki.extend_from_slice(&b.pk[..]);
        let mut long_sig = b.sig.to_vec();
        long_sig.push(0);
        let mut long_pk = b.pk.to_vec();
        long_pk.push(0);
        eprintln!(
            "aws118 raw-API: valid={} spki_pk={} sig+1byte={} sig-1byte={} pk+1byte={} pk-1byte={} empty_sig={}",
            aws118::verify(&b.pk[..], &b.msg, &b.sig[..]),
            aws118::verify(&spki, &b.msg, &b.sig[..]),
            aws118::verify(&b.pk[..], &b.msg, &long_sig),
            aws118::verify(&b.pk[..], &b.msg, &b.sig[..3308]),
            aws118::verify(&long_pk, &b.msg, &b.sig[..]),
            aws118::verify(&b.pk[..1951], &b.msg, &b.sig[..]),
            aws118::verify(&b.pk[..], &b.msg, &[]),
        );
    }

    let results: Vec<u8> = vec![0u8; n as usize];
    let labels: Vec<u8> = vec![0u8; n as usize];
    let done = AtomicU64::new(0);
    let t0 = std::time::Instant::now();
    let chunk = (n as usize).div_ceil(threads);
    std::thread::scope(|s| {
        for (ci, (res, lab)) in results.chunks(chunk).zip(labels.chunks(chunk)).enumerate() {
            let pool = &pool;
            let done = &done;
            // SAFETY: disjoint chunks, each written by exactly one thread.
            let res = unsafe { std::slice::from_raw_parts_mut(res.as_ptr() as *mut u8, res.len()) };
            let lab = unsafe { std::slice::from_raw_parts_mut(lab.as_ptr() as *mut u8, lab.len()) };
            s.spawn(move || {
                for (off, (rv, lv)) in res.iter_mut().zip(lab.iter_mut()).enumerate() {
                    let idx = (ci * chunk + off) as u64;
                    let (label, pk, msg, sig) = cases::make_case(pool, seed, idx);
                    let mut bits = 0u8;
                    if aws118::verify(&pk[..], &msg, &sig[..]) { bits |= 1; }
                    if nx::verify(&pk, &msg, &sig) { bits |= 2; }
                    if na::verify(&pk, &msg, &sig) { bits |= 4; }
                    if nc::verify(&pk, &msg, &sig) { bits |= 8; }
                    *rv = bits;
                    *lv = label;
                    done.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    let secs = t0.elapsed().as_secs_f64();
    std::fs::write(format!("{out_dir}/results118.bin"), &results).unwrap();
    std::fs::write(format!("{out_dir}/labels.bin"), &labels).unwrap();

    let mut per = vec![[0u64; 3]; LABELS.len()]; // total, all-accept, mismatch
    let mut mismatches = 0u64;
    for (i, (&r, &l)) in results.iter().zip(labels.iter()).enumerate() {
        per[l as usize][0] += 1;
        if r == 0b1111 { per[l as usize][1] += 1; }
        if r != 0 && r != 0b1111 {
            per[l as usize][2] += 1;
            mismatches += 1;
            if mismatches <= 20 { eprintln!("MISMATCH case {i} label {} bits {r:04b}", LABELS[l as usize]); }
        }
    }
    println!("cases={n} seed={seed} secs={secs:.1} mismatches(aws118,nx,na,nc)={mismatches}");
    for (i, p) in per.iter().enumerate() {
        println!("{:>26} total={:>9} accepted_by_all={:>9} mismatches={}", LABELS[i], p[0], p[1], p[2]);
    }
}
