# LVACS - Locally Verifiable Aggregating Concealed Signatures

A Rust implementation of a pairing-based signature scheme that allows signature aggregation over concealed signatures

## What it does

| Step | What happens |
|---|---|
| **KeyGen** | Generates a `(vk, sk)` pair for the underlying BLS signature scheme |
| **Sign** | Signs the message with `sk` using BLS |
| **Verify** |  Verifies the signed message with `vk` |
| **Convert** |  Converts a BLS signature into a concealed signature |
| **CVerify** | Verifies the concealed signature with `vk` |
| **Open** | Decommits the message commitment present in the concealed signature |
| **CAgg** |  Aggregates multiple concealed signatures into an aggregate signature |
| **CAggVf** | Verifies an aggregate signature with the respective `vk`s of all signers |
| **LAggOp** | Creates a local opening corresponding to a component concealed signature of the aggregate |
| **LAggVf** | Verifies a signature with its corresponding poening without requiring information about the other signatures involved |

---

## Requirements

- Rust toolchain ≥ 1.70 (`rustup` recommended)
- Cargo (included with Rust)
- No external system libraries required; cryptographic primitives are provided by the Arkworks Rust ecosystem

---

## Files

```
src/
  params.rs       — details about the underlying curve for BLS
  types.rs        — implementation of introduced types
  keys.rs         — BLS key structure info and generation algorithm
  signature.rs    — base BLS signature structure and signing algorithm 
  setup.rs        — setup of concealed signature parameters
  conceal.rs      — concealment algorithm
  open.rs         — concealed signature decommitment
  aggregate.rs    — aggregations and local opening generation
  verify.rs       — implementations of all verification algorithms
  scheme.rs       — top level wrapper for the entire LVACS scheme
  utils.rs        — helper functions for the scheme

benches/

examples/
  basic.rs        — implementation guide for the LVACS library

tests/
  verification.rs — tests for correctness of all implemented algorithms

structure.md      — formulas for all implemented funtions 
Cargo.toml        — dependencies
Cargo.lock        — pinned dependency versions
```

---

## Parameters
<!-- 
Parameters are passed at runtime via command-line flags. `√n` is derived automatically; `t` defaults to `n/2`.

| Flag | Default | Meaning | Constraint |
|---|---|---|---|
| `--n N` | 4 | Number of parties | Must be a perfect square |
| `--t T` | `n/2` | Shamir threshold | `1 ≤ t < n` |
| `--bsize B` | 3 | Max batch size (identities per batch) | `≥ 1` |

Compile-time constants in `src/param.rs` (`MAX_PARTIES`, `THRESHOLD`, `MAX_BSIZE`) are used only by the library tests and benchmarks. -->

---

## How to execute


<!-- # Build optimized (recommended — ~10× faster pairings)
cargo build --release

# Run with default parameters (n=4, t=2, bsize=3 — fast smoke test)
cargo run --release

# Run with explicit parameters (traitor defaults to n/4 = 9)
cargo run --release -- --n 36 --t 18 --bsize 20

# Run with n=64, threshold t=32, batch size 50, traitor at party 16
cargo run --release -- --n 64 --t 32 --bsize 50 --traitor 16 

# Run tests with output shown
cargo test -- --nocapture

# Run traitor tracing integration tests (slow: ~4s release per call)
cargo test test_trace -- --ignored
-->

```bash

# Run all unit tests
cargo test

# Run the example code
cargo run --example basic

# Run all benchmarks
cargo bench

# Run a single benchmark suite
cargo bench --bench bls
cargo bench --bench concealed
cargo bench --bench aggregate
cargo bench --bench verify

```

---

<!-- ## Demo output (`cargo run --release -- --n 36 --t 18 --bsize 20`)

> CPU: Intel Core i9-14900K · RAM: 32 GB

```
BTHTT — Full Pipeline
n=36  √n=6  t=18  bsize=20

Correctness: PASS


=== Trace (pirate coalition: parties 12..=30, traitor expected: 12) ===
Identified traitor parties: [12]  (expected [12], 13 probe cycles, ×20 batch)

=== Timings ===
KeyGen                              24.25ms
Digest (×20 identities)              4.34ms
Encrypt                             11.58ms
BPartDec (×19)                      19.86ms
  BPartDec per party                 1.05ms
Decrypt                             92.10ms
BatchEncrypt (×20)                 219.73ms
  BatchEncrypt per item             10.99ms
BatchDecrypt (×20)                    1.82s
  BatchDecrypt per item             91.14ms
Trace  (×13 probes, ×20 batch)       26.59s

=== Component Sizes  (G1=48B compressed, G2=96B compressed, GT=576B, Fr=32B) ===
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Component                    #G1    G1-B    #G2    G2-B   #GT    GT-B    #Fr    Fr-B    Total-B   Formula
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
MPK (scheme-one)               4(  192B)     1(   96B)    0(    0B)     0(    0B)      288B   4·G1 + G2
MPK (scheme-two)              14(  672B)     8(  768B)    0(    0B)     0(    0B)     1440B   (2√n+2)·G1 + (√n+2)·G2
MPK total                     18(  864B)     9(  864B)    0(    0B)     0(    0B)     1728B   (6+2√n)·G1 + (√n+3)·G2
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
MSK per party                  0(    0B)     1(   96B)    0(    0B)     3(   96B)      192B   3·Fr + G2
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
CT (scheme-one)                2(   96B)     0(    0B)    0(    0B)     0(    0B)       96B   2·G1
CT (scheme-two)               26( 1248B)    14( 1344B)    0(    0B)     0(    0B)     2592B   (4√n+2)·G1+2(√n+1)·G2
CT total                      28( 1344B)    14( 1344B)    1(  576B)     0(    0B)     3264B   (4+4√n)·G1+2(√n+1)·G2+GT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PartialDecKey                  0(    0B)     2(  192B)    0(    0B)     0(    0B)      192B   2·G2
Digest                         0(    0B)     1(   96B)    0(    0B)     0(    0B)       96B   G2
────────────────────────────────────────────────────────────────────────────────────────────────────────────────

=== Serialization Check (expected count·size == actual compressed bytes) ===
  ✓  MPK                     expected   1728 B   actual   1728 B
  ✓  MSK per party           expected    192 B   actual    192 B
  ✓  CT                      expected   3264 B   actual   3264 B
  ✓  PartialDecKey           expected    192 B   actual    192 B
  ✓  Digest                  expected     96 B   actual     96 B

```

> **Note:** `g2_tau_powers` (the CRS powers of τ in G2) are excluded from the MPK size — they are derivable from `g2_tau`. The single `g2_tau` element (1·G2 = 96B) is included in the scheme-one MPK.

--- -->

## Benchmarks

Benchmarks use [Criterion](https://github.com/bheisler/criterion.rs). The shared
loader in `benches/datasets/` generates deterministic messages locally and
derives the corresponding keys, signatures, concealed signatures, aggregates,
and local openings outside timed iterations.
The BLS, concealed, and verification suites use one fixed 32-signature fixture;
only aggregation and local-opening measurements sweep input sizes. Missing

```bash
cargo bench                         # run all suites
cargo bench --bench bls             # base BLS operations
cargo bench --bench concealed       # conversion, concealed verification, opening
cargo bench --bench aggregate       # aggregation and local openings
cargo bench --bench verify          # aggregate, local, and BLS verification
```

Criterion reports are written to `target/criterion/`.

## Cryptographic library

Built on the [arkworks](https://github.com/arkworks-rs) ecosystem:

| Crate | Purpose |
|---|---|
| `ark-bls12-381` | BLS12-381 pairing-friendly elliptic curve |
| `ark-ec` | Elliptic curve and pairing abstractions |
| `ark-ff` | Finite field arithmetic |
| `ark-std` | Standard utilities for Arkworks, including RNG support and testing utilities |