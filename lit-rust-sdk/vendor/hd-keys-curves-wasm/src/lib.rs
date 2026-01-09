mod derive;
#[cfg(feature = "ecops")]
mod ec_ops;

pub use derive::*;
#[cfg(feature = "ecops")]
pub use ec_ops::*;

pub use lit_rust_crypto;

#[cfg(not(any(
    feature = "p256",
    feature = "p384",
    feature = "k256",
    feature = "curve25519",
    feature = "bls",
    feature = "ed448",
    feature = "jubjub",
    feature = "decaf377",
    feature = "pasta"
)))]
compile_error!("At least one feature curve must be enabled");
