use core::cmp::min;

use crate::AffinePoint;

#[cfg(feature = "alloc")]
use alloc::vec;

use elliptic_curve::pkcs8::der::asn1::UintRef;
use elliptic_curve::pkcs8::der::Decode;
use elliptic_curve::pkcs8::der::DecodeValue;
use elliptic_curve::pkcs8::der::Encode;
use elliptic_curve::pkcs8::der::Length;
use elliptic_curve::pkcs8::der::Reader;
use elliptic_curve::pkcs8::der::Sequence;
use elliptic_curve::pkcs8::der::Writer;

use elliptic_curve::{
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
    digest: &'a [u8],
    cipher: &'a [u8],
}

impl<'a> Sequence<'a> for Cipher<'a> {}

impl<'a> EncodeValue for Cipher<'a> {
    fn value_len(&self) -> elliptic_curve::pkcs8::der::Result<Length> {
        UintRef::new(&self.x)?.encoded_len()?
            + UintRef::new(&self.y)?.encoded_len()?
            + OctetStringRef::new(&self.digest)?.encoded_len()?
            + OctetStringRef::new(&self.cipher)?.encoded_len()?
    }
    fn encode_value(&self, writer: &mut impl Writer) -> elliptic_curve::pkcs8::der::Result<()> {
        UintRef::new(&self.x)?.encode(writer)?;
        UintRef::new(&self.y)?.encode(writer)?;
        OctetStringRef::new(&self.digest)?.encode(writer)?;
        OctetStringRef::new(&self.cipher)?.encode(writer)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for Cipher<'a> {
    type Error = elliptic_curve::pkcs8::der::Error;

    fn decode_value<R: Reader<'a>>(
        decoder: &mut R,
        header: elliptic_curve::pkcs8::der::Header,
    ) -> core::result::Result<Self, Self::Error> {
        decoder.read_nested(header.length, |nr| {
            let x = UintRef::decode(nr)?.as_bytes();
            let y = UintRef::decode(nr)?.as_bytes();
            let digest = OctetStringRef::decode(nr)?.into();
            let cipher = OctetStringRef::decode(nr)?.into();
            Ok(Cipher {
                x,
                y,
                digest,
                cipher,
            })
        })
    }
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
    let mut ha = vec![0u8; digest_size];
    let encode_point = kpb.to_encoded_point(false);

    while offset < klen {
        hasher.update(encode_point.x().unwrap());
        hasher.update(encode_point.y().unwrap());
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
