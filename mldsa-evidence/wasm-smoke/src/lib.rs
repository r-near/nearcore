use near_crypto::{PublicKey, Signature, ml_dsa_65_from_seed};

const KAT_PUBKEY: &str = include_str!("kat_pubkey.txt");

/// Returns a bitmask: 1 = KAT pubkey matches, 2 = sign/verify ok,
/// 4 = tampered sig rejected, 8 = deterministic signing, 16 = FromStr sk roundtrip.
#[unsafe(no_mangle)]
pub extern "C" fn run() -> u32 {
    let mut seed = [b' '; 32];
    seed[..11].copy_from_slice(b"kat-seed-v1");
    let sk = ml_dsa_65_from_seed(&seed).unwrap();
    let pk = sk.public_key();
    let mut out = 0;
    if pk.to_string() == KAT_PUBKEY.trim() {
        out |= 1;
    }
    let msg = b"kat-message-v1";
    let sig = sk.sign(msg);
    if sig.verify(msg, &pk) {
        out |= 2;
    }
    let mut bytes = borsh::to_vec(&sig).unwrap();
    bytes[200] ^= 1;
    let bad: Signature = borsh::from_slice(&bytes).unwrap();
    if !bad.verify(msg, &pk) {
        out |= 4;
    }
    if sk.sign(msg) == sig {
        out |= 8;
    }
    let parsed: near_crypto::SecretKey = sk.to_string().parse().unwrap();
    let pk2: PublicKey = parsed.public_key();
    if pk2 == pk {
        out |= 16;
    }
    out
}
