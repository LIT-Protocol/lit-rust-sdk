# lit-frost

A Rust implementation of the [FROST (Flexible Round-Optimized Schnorr Threshold)](https://eprint.iacr.org/2020/852.pdf) signature scheme, providing threshold signatures across multiple elliptic curve ciphersuites.

[![Crates.io](https://img.shields.io/crates/v/lit-frost.svg)](https://crates.io/crates/lit-frost)
[![Documentation](https://docs.rs/lit-frost/badge.svg)](https://docs.rs/lit-frost)
[![License](https://img.shields.io/crates/l/lit-frost.svg)](LICENSE)

## Overview

FROST is a threshold signature scheme that allows a group of `n` signers to produce a single signature on a message, where the signature is valid if and only if at least `t` (threshold) of the signers have participated. This implementation is based on the [FROST paper](https://eprint.iacr.org/2020/852.pdf) and the [IETF FROST RFC](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/).

This crate provides a unified interface across multiple elliptic curve ciphersuites, making it easy to use FROST with your preferred cryptographic curve.

## Supported Signature Schemes

| Scheme | Description | Curve |
|--------|-------------|-------|
| `Ed25519Sha512` | EdDSA with SHA-512 | Curve25519 |
| `Ed448Shake256` | EdDSA with SHAKE-256 | Ed448-Goldilocks |
| `Ristretto25519Sha512` | Schnorr with SHA-512 | Ristretto255 |
| `K256Sha256` | Schnorr with SHA-256 | secp256k1 |
| `K256Taproot` | Bitcoin Taproot signatures | secp256k1 |
| `P256Sha256` | Schnorr with SHA-256 | NIST P-256 |
| `P384Sha384` | Schnorr with SHA-384 | NIST P-384 |
| `RedJubjubBlake2b512` | RedDSA with BLAKE2b-512 | Jubjub (Zcash Sapling) |
| `RedPallasBlake2b512` | RedDSA with BLAKE2b-512 | Pallas (Zcash Orchard) |
| `RedDecaf377Blake2b512` | RedDSA with BLAKE2b-512 | Decaf377 (Penumbra) |
| `SchnorrkelSubstrate` | Schnorrkel with Merlin | Ristretto255 (Polkadot/Substrate) |

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
lit-frost = "0.4"
```

### Features

- **`default`** - Full signing and verification capabilities
- **`verify_only`** - Signature verification only (excludes signing functionality for reduced binary size)

## How FROST Works

FROST requires **2 rounds** to complete a signature:

### Round 1: Commitment Generation
Each signer generates signing nonces and commitments. These can be:
- Pre-generated in batches using `Scheme::pregenerate_signing_nonces()` for efficiency
- Generated on-demand using `Scheme::signing_round1()`

### Round 2: Signature Share Generation
Each signer uses their secret share, nonces, and the collected commitments to generate a signature share using `Scheme::signing_round2()`.

### Aggregation
The signature shares are combined into a single threshold signature using `Scheme::aggregate()`. The resulting signature can be verified by anyone using `Scheme::verify()`.

## Usage Example

```rust
use lit_frost::{Scheme, KeyPackage, Identifier};
use std::num::NonZeroU16;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scheme = Scheme::Ed25519Sha512;
    let mut rng = rand::rngs::OsRng;
    
    // Generate keys with a trusted dealer (for demonstration)
    // In production, use distributed key generation (DKG)
    let threshold = 2u16;
    let num_signers = 3u16;
    let (secret_shares, verifying_key) = scheme
        .generate_with_trusted_dealer(threshold, num_signers, &mut rng)?;
    
    // Each signer performs Round 1
    let mut signing_commitments = Vec::new();
    let mut signing_nonces = Vec::new();
    
    for (id, secret_share) in &secret_shares {
        let (nonces, commitments) = scheme.signing_round1(secret_share, &mut rng)?;
        signing_nonces.push((id.clone(), nonces, secret_share.clone()));
        signing_commitments.push((id.clone(), commitments));
    }
    
    // Each signer performs Round 2
    let message = b"Hello, FROST!";
    let mut signature_shares = Vec::new();
    let mut verifying_shares = Vec::new();
    
    for (id, nonces, secret_share) in signing_nonces {
        let key_package = KeyPackage {
            identifier: id.clone(),
            secret_share: secret_share.clone(),
            verifying_key: verifying_key.clone(),
            threshold: NonZeroU16::new(threshold).unwrap(),
        };
        
        let sig_share = scheme.signing_round2(
            message,
            &signing_commitments,
            &nonces,
            &key_package,
        )?;
        
        signature_shares.push((id.clone(), sig_share));
        verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share)?));
    }
    
    // Aggregate signature shares
    let signature = scheme.aggregate(
        message,
        &signing_commitments,
        &signature_shares,
        &verifying_shares,
        &verifying_key,
    )?;
    
    // Verify the signature
    scheme.verify(message, &verifying_key, &signature)?;
    println!("Signature verified successfully!");
    
    Ok(())
}
```

## Key Types

| Type | Description |
|------|-------------|
| `Scheme` | Enum representing the supported signature schemes |
| `Identifier` | A unique identifier for each signer in the threshold group |
| `SigningShare` | A signer's secret share of the group signing key |
| `VerifyingShare` | A signer's public verification share |
| `VerifyingKey` | The group's public verification key |
| `SigningNonces` | Secret nonces used during signing (use only once!) |
| `SigningCommitments` | Public commitments to the signing nonces |
| `SignatureShare` | A signer's share of the threshold signature |
| `Signature` | The final aggregated threshold signature |
| `KeyPackage` | Contains all key material needed for a signer |

## Security Considerations

- **Nonce Reuse**: `SigningNonces` must **never** be reused. Reusing nonces will leak the signer's long-lived secret key.
- **Secret Storage**: `SigningShare` and `SigningNonces` must be stored securely and zeroized when no longer needed.
- **Threshold Selection**: Choose an appropriate threshold `t` based on your security requirements. A higher threshold provides better security but requires more signers to be available.

## Security Audit

This crate has been audited by Kudelski Security. The audit report is available in the [`audit/`](audit/) directory.

## Interoperability

This crate provides `From` and `TryFrom` implementations to convert between `lit-frost` types and types from popular cryptographic libraries including:

- `k256` (secp256k1)
- `p256` (NIST P-256)
- `p384` (NIST P-384)
- `curve25519-dalek`
- `ed448-goldilocks`
- `jubjub`
- `decaf377`
- `schnorrkel`

## References

- [FROST Paper](https://eprint.iacr.org/2020/852.pdf) - Original academic paper
- [IETF FROST RFC](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) - IETF standardization draft
- [ZCash FROST](https://frost.zfnd.org/) - ZCash Foundation's FROST resources

## License

Licensed under the [MIT License](LICENSE).
