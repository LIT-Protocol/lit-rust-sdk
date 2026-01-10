use crate::derive::HDDeriver;
use lit_rust_crypto::{hash2curve::ExpandMsgXmd, jubjub::Scalar};

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXmd<blake2::Blake2b512>>(msg, dst)
    }
}

#[cfg(test)]
mod test {
    use lit_rust_crypto::{
        elliptic_curve::{Field, Group},
        jubjub::{Scalar, SubgroupPoint},
    };

    use crate::HDDerivable;

    #[test]
    fn pippinger() {
        use rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaChaRng::from_rng(rand_core::OsRng).unwrap();

        let points = [SubgroupPoint::generator(); 3];

        for _ in 0..25 {
            let scalars = [
                Scalar::random(&mut rng),
                Scalar::random(&mut rng),
                Scalar::random(&mut rng),
            ];
            let expected = points[0] * scalars[0] + points[1] * scalars[1] + points[2] * scalars[2];

            let actual = SubgroupPoint::sum_of_products(&points, &scalars);

            assert_eq!(expected, actual);
        }
    }
}
