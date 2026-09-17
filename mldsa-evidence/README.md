# mldsa-native vs aws-lc-rs: test harnesses

Evidence for the `mldsa-native-backend-prototype` branch, which replaces
`aws-lc-rs` in `near-crypto` with a vendored `mldsa-native` (commit `834a90d`,
the same one `aws-lc-sys` 0.45 vendors).

Each crate here is outside the nearcore workspace and builds on its own. They
reference `core/mldsa-native-sys` and `core/crypto` from this branch by path,
so run them from this directory.

- `mldsa-diff/` — differential fuzz of ML-DSA-65 verification, plus secret-key
  parsing (`skcheck`) and the benchmark (`bench`). Compares aws-lc-rs 1.18.1
  against three mldsa-native builds: AVX2 arithmetic with AVX2 Keccak, AVX2
  arithmetic with C Keccak, and portable C.
- `mldsa-diff116/` — the same cases against aws-lc-rs 1.16.2, the version on
  the 2.14 release branch. It's a separate crate because cargo won't resolve
  two versions of aws-lc-rs in one graph.
- `wasm-smoke/` — builds `near-crypto` as a wasm32-unknown-unknown cdylib and
  runs keygen, signing, verification and `SecretKey` parsing under Node.
- `dup-link/` — shows that two `-sys` crates wrapping mldsa-native link into one
  binary with no error, one silently shadowing the other's symbols. Needs
  near-slip10 PR #22 checked out at `../../../near-slip10-pr22`.

## Results as run

- `results/fuzz/seed{2,3,4}/` — 3 x 10M cases, 24 mutation classes. 0
  accept/reject mismatches across all five verifiers.
- `results/bench/raw.txt` — 21 interleaved rounds, each sample its own process
  pinned to one core. `meta.txt` records machine load. Summarize with
  `python3 bench-summary.py results/bench/raw.txt`.

These ran on a Threadripper 3970X under WSL2, so treat the timings as
indicative. aarch64 was never built or measured.

## Running them

Build each crate with its own `CARGO_TARGET_DIR`, then point the scripts at it:

    BASE=/some/work/dir ./run-fuzz.sh
    CORE=6 BASE=/some/work/dir ./run-bench.sh

`run-fuzz.sh` expects `$BASE/fuzz-out/pool.bin`, which the fuzz binary writes on
its first run, and the release binaries under `$BASE/target-diff` and
`$BASE/target-diff116`.
