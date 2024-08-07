use core::cmp::min;

use alloc::vec::Vec;
use elliptic_curve::{sec1::ToEncodedPoint, Result};
use sm3::digest::DynDigest;

use crate::AffinePoint;

#[cfg(feature = "arithmetic")]
mod decrypting;
#[cfg(feature = "arithmetic")]
mod encrypting;

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
    let mut ha = Vec::with_capacity(hasher.output_size());
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
