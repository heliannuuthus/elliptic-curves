use crate::arithmetic::field::FieldElement;
use crate::{AffinePoint, EncodedPoint, FieldBytes, NonZeroScalar, PublicKey, Scalar, SecretKey};
use alloc::boxed::Box;
use alloc::vec::Vec;
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::Error;
use elliptic_curve::{bigint::U256, sec1::ToEncodedPoint, Group, Result};
use primeorder::PrimeField;
use sm3::digest::DynDigest;
use sm3::{Digest, Sm3};

use super::encrypting::EncryptingKey;
use super::{kdf, Mode};

pub struct DecryptingKey {
    secret_scalar: NonZeroScalar,
    encrytingKey: EncryptingKey,
    mode: Mode,
    digest: Box<dyn DynDigest + Send + Sync>,
}

impl DecryptingKey {
    pub fn new(secret_key: SecretKey) -> Self {
        Self::new_with_mode(secret_key.to_nonzero_scalar(), Mode::C1C2C3)
    }

    pub fn new_with_mode(secret_scalar: NonZeroScalar, mode: Mode) -> Self {
        Self::new_with_mode_and_hash::<Sm3>(secret_scalar, mode)
    }

    pub fn new_with_mode_and_hash<D: 'static + Digest + DynDigest + Send + Sync>(
        secret_scalar: NonZeroScalar,
        mode: Mode,
    ) -> Self {
        Self {
            secret_scalar,
            encrytingKey: EncryptingKey::new_with_mode_and_hash::<D>(
                PublicKey::from_secret_scalar(&secret_scalar),
                mode,
            ),
            mode,
            digest: Box::new(D::new()),
        }
    }

    /// Parse signing key from big endian-encoded bytes.
    pub fn from_bytes(bytes: &FieldBytes) -> Result<Self> {
        Self::from_slice(bytes)
    }

    /// Parse signing key from big endian-encoded byte slice containing a secret
    /// scalar value.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let secret_scalar = NonZeroScalar::try_from(slice).map_err(|_| Error)?;
        Self::from_nonzero_scalar(secret_scalar)
    }

    /// Create a signing key from a non-zero scalar.
    pub fn from_nonzero_scalar(secret_scalar: NonZeroScalar) -> Result<Self> {
        Ok(Self::new_with_mode(secret_scalar, Mode::C1C2C3))
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.secret_scalar.to_bytes()
    }

    /// Borrow the secret [`NonZeroScalar`] value for this key.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn as_nonzero_scalar(&self) -> &NonZeroScalar {
        &self.secret_scalar
    }

    /// Get the [`VerifyingKey`] which corresponds to this [`SigningKey`].
    pub fn encrypting_key(&self) -> &EncryptingKey {
        &self.encrytingKey
    }

    pub fn decrypt(&mut self, msg: &mut [u8]) -> Result<Vec<u8>> {
        decrypt(&self.secret_scalar, self.mode, &mut *self.digest, msg)
    }
}

fn decrypt(
    secret_scalar: &Scalar,
    mode: Mode,
    hasher: &mut dyn DynDigest,
    cipher: &mut [u8],
) -> Result<Vec<u8>> {
    let q = U256::from_be_hex(FieldElement::MODULUS);
    let c1_len = q.bits() * 2 + 1;

    let (c1, c) = cipher.split_at_mut(c1_len as usize);
    let encoded_c1 = EncodedPoint::from_bytes(c1).unwrap();
    // verify that point c1 satisfies the elliptic curve
    let mut c1_point = AffinePoint::from_encoded_point(&encoded_c1).unwrap();
    let s = c1_point * Scalar::from_uint(U256::from_u32(FieldElement::S)).unwrap();

    if s.is_identity().into() {
        return Err(Error);
    }

    c1_point = (c1_point * secret_scalar).to_affine();

    let digest_size = hasher.output_size();

    let (c2, c3) = match mode {
        Mode::C1C3C2 => c.split_at_mut(digest_size),
        Mode::C1C2C3 => c.split_at_mut(c.len() - digest_size),
    };

    kdf(hasher, c1_point, c2)?;

    let mut c3_checked = Vec::with_capacity(digest_size);
    let encode_point = c1_point.to_encoded_point(false);

    hasher.update(encode_point.x().unwrap());
    hasher.update(c2);
    hasher.update(encode_point.x().unwrap());
    hasher
        .finalize_into_reset(&mut c3_checked)
        .map_err(|_e| Error)?;

    let checked =
        c3_checked
            .iter()
            .zip(c3)
            .fold(0, |mut check, (&c3_byte, &mut c3checked_byte)| {
                check |= c3_byte ^ c3checked_byte;
                check
            });

    if checked != 0 {
        return Err(Error);
    }
    Ok(c2.to_vec())
}
