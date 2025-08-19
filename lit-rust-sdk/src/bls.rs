use crate::types::JsonSignSessionKeyResponseV1;
use blsful::{Bls12381G2Impl, PublicKey, Signature, SignatureSchemes, TimeCryptCiphertext};
use eyre::Result;

pub fn combine(
    signature_shares: &[JsonSignSessionKeyResponseV1],
) -> Result<Signature<Bls12381G2Impl>> {
    combine_iter(signature_shares.iter())
}

pub fn combine_iter<I, T>(signature_shares: I) -> Result<Signature<Bls12381G2Impl>>
where
    I: Iterator<Item = T>,
    T: core::borrow::Borrow<JsonSignSessionKeyResponseV1>,
{
    let shares = signature_shares
        .map(|s| s.borrow().signature_share)
        .collect::<Vec<_>>();
    let sig = Signature::from_shares(&shares)?;
    Ok(sig)
}

pub fn verify(
    public_key: &[u8],
    message: &[u8],
    signature: &Signature<Bls12381G2Impl>,
) -> Result<()> {
    let pk = PublicKey::try_from(public_key)?;
    signature.verify(&pk, message)?;
    Ok(())
}

pub fn encrypt(encryption_key: &[u8], message: &[u8], identity: &[u8]) -> Result<Vec<u8>> {
    let ek = PublicKey::<Bls12381G2Impl>::try_from(encryption_key)?;
    let ciphertext =
        ek.encrypt_time_lock(SignatureSchemes::ProofOfPossession, message, identity)?;
    let ciphertext = serde_bare::to_vec(&ciphertext)?;
    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &[u8], decryption_key: &[u8]) -> Result<Vec<u8>> {
    let dk = Signature::<Bls12381G2Impl>::try_from(decryption_key)?;
    let ciphertext: TimeCryptCiphertext<Bls12381G2Impl> = serde_bare::from_slice(ciphertext)?;
    let message =
        Option::<Vec<u8>>::from(ciphertext.decrypt(&dk)).ok_or(eyre::eyre!("Unable to decrypt"))?;
    Ok(message)
}
