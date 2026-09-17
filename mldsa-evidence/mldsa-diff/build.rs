use std::path::PathBuf;

// Extra mldsa-native variants for comparison, compiled from the same sources as
// the prototype sys crate but with distinct symbol prefixes:
//   mldsa65c: portable C only
//   mldsa65a: native AVX2 arithmetic, C Keccak (closest to AWS-LC 0.45's split)
fn main() {
    let sys = PathBuf::from("../../core/mldsa-native-sys");
    let mldsa = sys.join("mldsa-native/mldsa");
    let csrc = sys.join("csrc");
    println!("cargo:rerun-if-changed=build.rs");
    for (prefix, native) in [("mldsa65c", false), ("mldsa65a", true)] {
        let mut b = cc::Build::new();
        b.include(&csrc)
            .include(&mldsa)
            .include(mldsa.join("src"))
            .define("MLD_CONFIG_FILE", Some("\"near_mldsa_config.h\""))
            .define("MLD_CONFIG_NAMESPACE_PREFIX", Some(prefix))
            .file(mldsa.join("mldsa_native.c"))
            .std("c90");
        if native {
            b.define("NEAR_MLDSA_NATIVE", None);
            b.file(mldsa.join("mldsa_native_asm.S"));
        }
        b.compile(prefix);
    }
}
