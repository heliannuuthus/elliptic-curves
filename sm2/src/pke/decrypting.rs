use core::fmt::{self, Debug};

use crate::arithmetic::field::FieldElement;
use crate::{AffinePoint, EncodedPoint, FieldBytes, NonZeroScalar, PublicKey, Scalar, SecretKey};

use alloc::vec::Vec;
use elliptic_curve::ops::Reduce;
use elliptic_curve::pkcs8::der::Decode;
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::subtle::{Choice, ConstantTimeEq};
use elliptic_curve::Error;
use elliptic_curve::{bigint::U256, sec1::ToEncodedPoint, Group, Result};
use primeorder::PrimeField;

use sm3::digest::DynDigest;
use sm3::{Digest, Sm3};

use super::encrypting::EncryptingKey;
use super::{kdf, vec, Cipher, Mode};

#[derive(Clone)]
pub struct DecryptingKey {
    secret_scalar: NonZeroScalar,
    encryting_key: EncryptingKey,
    mode: Mode,
}

impl DecryptingKey {
    pub fn new(secret_key: SecretKey) -> Self {
        Self::new_with_mode(secret_key.to_nonzero_scalar(), Mode::C1C3C2)
    }

    pub fn new_with_mode(secret_scalar: NonZeroScalar, mode: Mode) -> Self {
        Self {
            secret_scalar,
            encryting_key: EncryptingKey::new_with_mode(
                PublicKey::from_secret_scalar(&secret_scalar),
                mode,
            ),
            mode,
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
        Ok(Self::new_with_mode(secret_scalar, Mode::C1C3C2))
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

    /// Get the [`EncryptingKey`] which corresponds to this [`DecryptingKey`].
    pub fn encrypting_key(&self) -> &EncryptingKey {
        &self.encryting_key
    }

    /// Decrypt inplace
    pub fn decrypt(&self, ciphertext: &mut [u8]) -> Result<Vec<u8>> {
        self.decrypt_digest::<Sm3>(ciphertext)
    }
    /// Decrypt inplace
    pub fn decrypt_digest<D>(&self, ciphertext: &mut [u8]) -> Result<Vec<u8>>
    where
        D: 'static + Digest + DynDigest + Send + Sync,
    {
        let mut digest = D::new();
        decrypt(&self.secret_scalar, self.mode, &mut digest, ciphertext)
    }

    pub fn decrypt_asna1(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_asna1_digest::<Sm3>(ciphertext)
    }

    /// Decrypt inplace
    pub fn decrypt_asna1_digest<D>(&self, ciphertext: &[u8]) -> Result<Vec<u8>>
    where
        D: 'static + Digest + DynDigest + Send + Sync,
    {
        let cipher =
            Cipher::from_der(&ciphertext).map_err(|e| elliptic_curve::pkcs8::Error::from(e))?;

        let mut cipher = match self.mode {
            Mode::C1C2C3 => [&[0x04], cipher.x, cipher.y, cipher.cipher, cipher.digest].concat(),
            Mode::C1C3C2 => [&[0x04], cipher.x, cipher.y, cipher.digest, cipher.cipher].concat(),
        };

        Ok(self.decrypt_digest::<D>(&mut cipher)?)
    }
}

//
// Other trait impls
//

impl AsRef<EncryptingKey> for DecryptingKey {
    fn as_ref(&self) -> &EncryptingKey {
        &self.encryting_key
    }
}

impl ConstantTimeEq for DecryptingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret_scalar.ct_eq(&other.secret_scalar)
    }
}

impl Debug for DecryptingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptingKey")
            .field("private_key", &self.secret_scalar.as_ref())
            .field("encrypting_key", &self.encrypting_key())
            .finish_non_exhaustive()
    }
}

/// Constant-time comparison
impl Eq for DecryptingKey {}
impl PartialEq for DecryptingKey {
    fn eq(&self, other: &DecryptingKey) -> bool {
        self.ct_eq(other).into()
    }
}

fn decrypt(
    secret_scalar: &Scalar,
    mode: Mode,
    hasher: &mut dyn DynDigest,
    cipher: &mut [u8],
) -> Result<Vec<u8>> {
    let q = U256::from_be_hex(FieldElement::MODULUS);
    let c1_len = (q.bits() + 7) / 8 * 2 + 1;

    let (c1, c) = cipher.split_at_mut(c1_len as usize);
    let encoded_c1 = EncodedPoint::from_bytes(c1).unwrap();

    // verify that point c1 satisfies the elliptic curve
    let mut c1_point = AffinePoint::from_encoded_point(&encoded_c1).unwrap();

    let s = c1_point * Scalar::reduce(U256::from_u32(FieldElement::S));

    if s.is_identity().into() {
        return Err(Error);
    }

    c1_point = (c1_point * secret_scalar).to_affine();

    let digest_size = hasher.output_size();

    let (c2, c3) = match mode {
        Mode::C1C3C2 => {
            let (c3, c2) = c.split_at_mut(digest_size);
            (c2, c3)
        }
        Mode::C1C2C3 => c.split_at_mut(c.len() - digest_size),
    };

    kdf(hasher, c1_point, c2)?;

    let mut c3_checked = vec![0u8; digest_size];
    let encode_point = c1_point.to_encoded_point(false);

    hasher.update(&encode_point.x().unwrap());
    hasher.update(c2);
    hasher.update(&encode_point.y().unwrap());
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
