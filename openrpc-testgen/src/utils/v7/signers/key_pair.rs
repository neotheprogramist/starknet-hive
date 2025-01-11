use crypto_bigint::{Encoding, NonZero, U256};
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::stark_curve::StarkCurve;
use rand::{rngs::StdRng, Rng, SeedableRng};
// use starknet_types_core::curve::{get_public_key, EcdsaSignError, Signature, Signer};
use crypto_utils::curve::signer::{get_public_key, EcdsaSignError, Signature, Signer};
use starknet_types_core::felt::Felt;
#[derive(Debug, Clone, Copy)]
pub struct SigningKey {
    secret_scalar: Felt,
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    scalar: Felt,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("invalid path")]
    InvalidPath,
    #[error("invalid decrypted secret scalar")]
    InvalidScalar,
}

impl SigningKey {
    /// Generates a new key pair from a cryptographically secure RNG.
    pub fn from_random() -> Self {
        const PRIME: NonZero<U256> = NonZero::from_uint(U256::from_be_hex(
            "0800000000000011000000000000000000000000000000000000000000000001",
        ));

        let mut rng = StdRng::from_entropy();
        let mut buffer = [0u8; 32];
        rng.fill(&mut buffer);

        let random_u256 = U256::from_be_slice(&buffer);
        let secret_scalar = random_u256.rem(&PRIME);

        // It's safe to unwrap here as we're 100% sure it's not out of range
        let secret_scalar = Felt::from_bytes_be_slice(&secret_scalar.to_be_bytes());

        Self { secret_scalar }
    }

    pub fn from_secret_scalar(secret_scalar: Felt) -> Self {
        Self { secret_scalar }
    }
    pub fn secret_scalar(&self) -> Felt {
        self.secret_scalar
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_scalar(get_public_key(&self.secret_scalar))
    }

    pub fn sign(&self, hash: &Felt) -> Result<Signature, EcdsaSignError> {
        StarkCurve::ecdsa_sign(&self.secret_scalar, hash).map(|sig| sig.into())
    }
}

impl VerifyingKey {
    pub fn from_scalar(scalar: Felt) -> Self {
        Self { scalar }
    }

    pub fn scalar(&self) -> Felt {
        self.scalar
    }

    // pub fn verify(&self, hash: &Felt, signature: &Signature) -> Result<bool, EcdsaVerifyError> {
    //     ecdsa_verify(&self.scalar, hash, signature)
    // }
}
