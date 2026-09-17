fn main() {
    let seed = [7u8; 32];
    let (mut pk1, mut sk1) = ([0u8; 1952], [0u8; 4032]);
    near_slip10_mldsa_native_sys::ml_dsa_65_keypair_from_seed(&seed, &mut pk1, &mut sk1).unwrap();
    let (mut pk2, mut sk2) = ([0u8; 1952], [0u8; 4032]);
    near_mldsa_native_sys::keypair_from_seed(&seed, &mut pk2, &mut sk2).unwrap();
    println!("same pk: {} verify: {}", pk1 == pk2, uses_full_api());
}

#[allow(dead_code)]
fn uses_full_api() -> bool {
    let (mut pk, mut sk) = ([0u8; 1952], [0u8; 4032]);
    near_mldsa_native_sys::keypair_from_seed(&[1u8; 32], &mut pk, &mut sk).unwrap();
    let mut sig = [0u8; 3309];
    near_mldsa_native_sys::sign(&sk, b"m", &[0u8; 32], &mut sig).unwrap();
    near_mldsa_native_sys::verify(&pk, b"m", &sig)
}
