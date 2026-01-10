use crate::derive::HDDeriver;
use lit_rust_crypto::{
    decaf377::Fr as Scalar,
    hash2curve::{ExpandMsg, ExpandMsgXmd, Expander},
};

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let dst = [dst];
        let mut expander = ExpandMsgXmd::<blake2::Blake2b512>::expand_message(&[msg], &dst, 64)
            .expect("valid xmd");
        let mut bytes = [0u8; 64];
        expander.fill_bytes(&mut bytes);
        Scalar::from_le_bytes_mod_order(&bytes)
    }
}

#[cfg(test)]
mod test {
    use lit_rust_crypto::{
        decaf377::{Element as ProjectivePoint, Fr as Scalar},
        ff::Field,
    };

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
