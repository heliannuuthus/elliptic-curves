use core::fmt::Debug;

use crate::pke::{kdf, vec};
use crate::{AffinePoint, Scalar};
use crate::{ProjectivePoint, PublicKey, Sm2};

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};

use elliptic_curve::pkcs8::der::Encode;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::{
    bigint::{RandomBits, Uint, Zero, U256},
    ops::MulByGenerator,
    rand_core, Curve,
};
use elliptic_curve::{Error, Result};

use sm3::digest::{Digest, DynDigest};
use sm3::Sm3;

use super::{Cipher, Mode};

#[derive(Clone, Debug)]
pub struct EncryptingKey {
    public_key: PublicKey,
    mode: Mode,
}

impl EncryptingKey {
    /// Initialize [`EncryptingKey`] from PublicKey
    pub fn new(public_key: PublicKey) -> Self {
        Self::new_with_mode(public_key, Mode::C1C2C3)
    }

    /// Initialize [`EncryptingKey`] from PublicKey and set Encryption mode
    pub fn new_with_mode(public_key: PublicKey, mode: Mode) -> Self {
        Self { public_key, mode }
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

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_digest::<Sm3>(msg)
    }

    pub fn encrypt_asna1(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_asna1_digest::<Sm3>(msg)
    }

    pub fn encrypt_digest<D>(&self, msg: &[u8]) -> Result<Vec<u8>>
    where
        D: 'static + Digest + DynDigest + Send + Sync,
    {
        let mut digest = D::new();
        encrypt(&self.public_key, self.mode, &mut digest, msg)
    }

    pub fn encrypt_asna1_digest<D>(&self, msg: &[u8]) -> Result<Vec<u8>>
    where
        D: 'static + Digest + DynDigest + Send + Sync,
    {
        let mut digest = D::new();
        let cipher = encrypt(&self.public_key, self.mode, &mut digest, msg)?;
        let digest_size = digest.output_size();
        let (_, cipher) = cipher.split_at(1);
        let (x, cipher) = cipher.split_at(32);
        let (y, cipher) = cipher.split_at(32);
        let (digest, cipher) = match self.mode {
            Mode::C1C2C3 => {
                let (cipher, digest) = cipher.split_at(cipher.len() - digest_size);
                (digest, cipher)
            }
            Mode::C1C3C2 => cipher.split_at(digest_size),
        };
        Ok(Cipher {
            x,
            y,
            digest,
            cipher,
        }
        .to_der()
        .map_err(|e| elliptic_curve::pkcs8::Error::from(e))?)
    }
}

impl From<PublicKey> for EncryptingKey {
    fn from(value: PublicKey) -> Self {
        Self::new(value)
    }
}

fn encrypt(
    public_key: &PublicKey,
    mode: Mode,
    digest: &mut dyn DynDigest,
    msg: &[u8],
) -> Result<Vec<u8>> {
    const N_BYTES: u32 = (Sm2::ORDER.bits() + 7) / 8;
    let mut c1 = vec![0; (N_BYTES * 2 + 1) as usize];
    let mut c2 = msg.to_owned();
    let mut kpb: AffinePoint;
    loop {
        let k = Scalar::from_uint(next_k(N_BYTES)).unwrap();
        let kg = ProjectivePoint::mul_by_generator(&k).to_affine();
        let uncompress_kg = kg.to_encoded_point(false);
        c1.copy_from_slice(uncompress_kg.as_bytes());
        let public_pp = public_key.to_projective();
        kpb = (public_pp * &k).to_affine();

        kdf(digest, kpb, &mut c2)?;

        // if all of t are 0, xor(c2) == c2

        if c2.iter().zip(msg).any(|(pre, cur)| pre != cur) {
            break;
        }
    }
    let encode_point = kpb.to_encoded_point(false);

    let mut c3 = vec![0; digest.output_size()];
    digest.update(encode_point.x().unwrap());
    digest.update(msg);
    digest.update(encode_point.y().unwrap());
    digest.finalize_into_reset(&mut c3).map_err(|_e| Error)?;

    Ok(match mode {
        Mode::C1C2C3 => [c1.as_slice(), &c2, &c3].concat().to_vec(),
        Mode::C1C3C2 => [c1.as_slice(), &c3, &c2].concat().to_vec(),
    })
}

fn next_k(bit_length: u32) -> Uint<4> {
    loop {
        let k = U256::random_bits(&mut rand_core::OsRng, bit_length);
        if k.is_zero().unwrap_u8() == 0 && k <= Sm2::ORDER {
            return k;
        }
    }
}
