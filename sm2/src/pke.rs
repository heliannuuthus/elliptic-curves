use core::cmp::min;

use crate::AffinePoint;
use crate::U32;
#[cfg(feature = "alloc")]
use alloc::vec;
use alloc::vec::Vec;
use elliptic_curve::bigint::Integer;
use elliptic_curve::bigint::Uint;
use elliptic_curve::bigint::U256;
use elliptic_curve::pkcs8::der::asn1::UintRef;
use elliptic_curve::pkcs8::der::Decode;
use elliptic_curve::pkcs8::der::Encode;
use elliptic_curve::pkcs8::der::Length;
use elliptic_curve::pkcs8::der::Reader;
use elliptic_curve::pkcs8::der::Writer;
use elliptic_curve::pkcs8::Version;
use elliptic_curve::FieldBytesEncoding;
use elliptic_curve::{
    array::Array,
    pkcs8::der::{asn1::OctetStringRef, EncodeValue},
    sec1::ToEncodedPoint,
    Result,
};
use sm3::digest::DynDigest;

#[cfg(feature = "arithmetic")]
mod decrypting;
#[cfg(feature = "arithmetic")]
mod encrypting;

#[cfg(feature = "arithmetic")]
pub use self::{decrypting::DecryptingKey, encrypting::EncryptingKey};

/// https://search.r-project.org/CRAN/refmans/smcryptoR/html/sm2_encrypt_asn1.html
pub struct Cipher<'a> {
    x: &'a [u8],
    y: &'a [u8],
    sm3: &'a [u8],
    secret: &'a [u8],
}

impl<'a> Encode for Cipher<'a> {
    fn encoded_len(&self) -> elliptic_curve::pkcs8::der::Result<Length> {
        Length::new((self.x.len() + self.y.len() + self.sm3.len() + self.secret.len()) as u16)
            .encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> elliptic_curve::pkcs8::der::Result<()> {
        UintRef::new(self.x)?.encode(writer)?;
        UintRef::new(self.y)?.encode(writer)?;
        OctetStringRef::new(self.sm3)?.encode(writer)?;
        OctetStringRef::new(self.secret)?.encode(writer)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for Cipher<'a> {
    type Error = elliptic_curve::pkcs8::der::Error;

    fn decode<R: Reader<'a>>(decoder: &mut R) -> core::result::Result<Self, Self::Error> {}
}

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    C1C2C3,
    C1C3C2,
}

fn kdf(hasher: &mut dyn DynDigest, kpb: AffinePoint, c2: &mut [u8]) -> Result<()> {
    let klen = c2.len();
    let mut ct: i32 = 0x00000001;
    let mut offset = 0;
    let digest_size = hasher.output_size();
    let mut ha = vec![0u8; hasher.output_size()];
    let encode_point = kpb.to_encoded_point(false);

    while offset < klen {
        hasher.update(&encode_point.x().unwrap());
        hasher.update(&encode_point.y().unwrap());
        hasher.update(&ct.to_be_bytes());
        hasher
            .finalize_into_reset(&mut ha)
            .map_err(|_e| elliptic_curve::Error)?;

        let xor_len = min(digest_size, klen - offset);
        xor(c2, &ha, offset, xor_len);
        offset += xor_len;
        ct += 1;
    }
    Ok(())
}

fn xor(c2: &mut [u8], ha: &[u8], offset: usize, xor_len: usize) {
    for i in 0..xor_len {
        c2[offset + i] ^= ha[i];
    }
}
