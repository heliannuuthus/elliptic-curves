use crate::pke::kdf;
use crate::{AffinePoint, Scalar};
use crate::{ProjectivePoint, PublicKey, Sm2};
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec::Vec;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::{
    bigint::{RandomBits, Uint, Zero, U256},
    ops::MulByGenerator,
    rand_core, Curve,
};
use elliptic_curve::{Error, Result};

use sm3::digest::{Digest, DynDigest};
use sm3::Sm3;

use super::Mode;

pub struct EncryptingKey {
    public_key: PublicKey,
    mode: Mode,
    digest: Box<dyn DynDigest + Send + Sync>,
}

impl EncryptingKey {
    /// Initialize [`EncryptingKey`] from PublicKey
    pub fn new(public_key: PublicKey) -> Self {
        Self::new_with_mode(public_key, Mode::C1C2C3)
    }

    /// Initialize [`EncryptingKey`] from PublicKey and set Encryption mode
    pub fn new_with_mode(public_key: PublicKey, mode: Mode) -> Self {
        Self::new_with_mode_and_hash::<Sm3>(public_key, mode)
    }

    /// Initialize [`EncryptingKey`] from PublicKey and set Encryption mode then set hasher
    pub fn new_with_mode_and_hash<D: 'static + Digest + DynDigest + Send + Sync>(
        public_key: PublicKey,
        mode: Mode,
    ) -> Self {
        Self {
            public_key,
            mode,
            digest: Box::new(D::new()),
        }
    }

    /// Initialize [`VerifyingKey`] from a SEC1-encoded public key.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let public_key = PublicKey::from_sec1_bytes(bytes).map_err(|_| Error)?;
        Ok(Self::new(public_key))
    }

    /// Initialize [`VerifyingKey`] from an affine point.
    ///
    /// Returns an [`Error`] if the given affine point is the additive identity
    /// (a.k.a. point at infinity).
    pub fn from_affine(affine: AffinePoint) -> Result<Self> {
        let public_key = PublicKey::from_affine(affine).map_err(|_| Error)?;
        Ok(Self::new(public_key))
    }

    /// Borrow the inner [`AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &AffinePoint {
        self.public_key.as_affine()
    }

    /// Convert this [`VerifyingKey`] into the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
    /// (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    #[cfg(feature = "alloc")]
    pub fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.public_key.to_sec1_bytes()
    }

    pub fn encrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        encrypt(self.public_key, self.mode, &mut *self.digest, msg)
    }
}

impl From<PublicKey> for EncryptingKey {
    fn from(value: PublicKey) -> Self {
        Self::new(value)
    }
}

fn encrypt(
    public_key: PublicKey,
    mode: Mode,
    hasher: &mut dyn DynDigest,
    msg: &[u8],
) -> Result<Vec<u8>> {
    const N_BYTES: u32 = (Sm2::ORDER.bits() + 7) / 8;
    let mut c1;
    let mut c2 = msg.to_owned();
    let mut kpb: AffinePoint;
    loop {
        let k = Scalar::from_uint(next_k(N_BYTES)).unwrap();
        let kg = ProjectivePoint::mul_by_generator(&k).to_affine();
        c1 = kg.to_bytes();
        let public_pp = public_key.to_projective();
        kpb = (public_pp * &k).to_affine();
        kdf(hasher, kpb, &mut c2)?;

        // if all of t are 0, xor(c2) == c2

        if c2.iter().zip(msg).any(|(pre, cur)| pre != cur) {
            break;
        }
    }
    let encode_point = kpb.to_encoded_point(false);

    let mut c3 = Vec::with_capacity(hasher.output_size());
    hasher.update(encode_point.x().unwrap());
    hasher.update(msg);
    hasher.update(encode_point.x().unwrap());

    hasher
        .finalize_into_reset(&mut c3)
        .map_err(|_e| elliptic_curve::Error)?;

    let mut result = Vec::with_capacity(c1.len() + c2.len() + c3.len());
    match mode {
        Mode::C1C2C3 => {
            result.extend_from_slice(c1.as_slice());
            result.extend_from_slice(&c2);
            result.extend_from_slice(&c3);
        }
        Mode::C1C3C2 => {
            result.extend_from_slice(c1.as_slice());
            result.extend_from_slice(&c3);
            result.extend_from_slice(&c2);
        }
    }
    Ok(result)
}

fn next_k(bit_length: u32) -> Uint<4> {
    let mut k: Uint<4>;
    loop {
        k = U256::random_bits(&mut rand_core::OsRng, bit_length);
        if !(k == U256::zero() || k > Sm2::ORDER) {
            return k;
        }
    }
}
