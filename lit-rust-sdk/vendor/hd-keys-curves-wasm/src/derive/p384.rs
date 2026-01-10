use crate::derive::HDDeriver;
use lit_rust_crypto::{
    hash2curve::{ExpandMsgXmd, GroupDigest},
    p384::{NistP384, Scalar},
};

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        NistP384::hash_to_scalar::<ExpandMsgXmd<sha2::Sha384>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

#[cfg(test)]
mod test {
    use lit_rust_crypto::elliptic_curve::Field;
    use lit_rust_crypto::p384::{ProjectivePoint, Scalar};

    use crate::HDDerivable;

    #[test]
    fn pippinger() {
        use rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaChaRng::from_rng(rand_core::OsRng).unwrap();

        let points = [ProjectivePoint::GENERATOR; 3];

        for _ in 0..25 {
            let scalars = [
                Scalar::random(&mut rng),
                Scalar::random(&mut rng),
                Scalar::random(&mut rng),
            ];
            let expected = points[0] * scalars[0] + points[1] * scalars[1] + points[2] * scalars[2];

            let actual = ProjectivePoint::sum_of_products(&points, &scalars);

            assert_eq!(expected, actual);
        }
    }
}
