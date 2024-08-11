#![cfg(feature = "pke")]

use elliptic_curve::ops::Reduce;
use elliptic_curve::{CurveArithmetic, NonZeroScalar};
use hex_literal::hex;
use proptest::prelude::*;
use sm2::pke::Mode;
use sm2::{
    pke::{DecryptingKey, EncryptingKey},
    PublicKey, Sm2,
};
use sm2::{AffinePoint, Scalar, SecretKey, U256};

// sec1 public key b
const PUBLIC_KEY: [u8; 65] = hex!("044b0b5d9b5b13c62238c86ecb7161ce0831fb1a0f29441ddd212cecbad2eea0b99e792d0e2dcfc70555ac24b536d7476e99ba8562f75de5ce8f0595909138ec0c");
const PRIVATE_KEY: [u8; 32] =
    hex!("46AE010C87F8D73FE3124C52FF6695DD839D73748FD40D6B2A3D7CC3E0233F1E");
const MSG: &[u8] = b"plaintext";

// uncompress, starts with 04
const CIPHER: [u8; 106] = hex!("0437c84a1ee61a707cf5819b64a56f82186e69771775119c82139b6a56f5ff64fec5f3b1c5783648fc306be5a0a4e14c219bbecd62670bc8d8d0fe56d67e6baeff8ba118c7e79dc3abacbf1f4e13533081862158f720fd32705fc318f7f1f617a8734bbcc7569d0665e1");
// openssl pkeyutl -encrypt -in - -inkey sm2.key -out cipher.txt
const ASN1_CIPHER: [u8; 116] = hex!("3072022000d9df58aa6af5f94534bc500bf31233c8824379b2494edd2ff29526ce04d424022100b3049c48f5d69c65456382513e4eba827972ae86a38c7a886cf6ed50fb5fe06004206886509211229740694b3ac17bec1ea59ce42c21d1566c15fbd65c5e5d90f6390409a02ecfa10309326f43");
// 3071022007868d682d1d613148a5b993959f9ba344fbb2ef4150238f4f0d453d1564f9d2022000cbbb8903f07f0104db3b619296247f2f43477649b9b363d73af3ddba7597ac042006af6a9af1eb46c8fceba124e8743985581d5e2b88682a9bc44c0ff6cb3981d2040947bc9c69914d3a2ec5
// 3072022000d9df58aa6af5f94534bc500bf31233c8824379b2494edd2ff29526ce04d424022100b3049c48f5d69c65456382513e4eba827972ae86a38c7a886cf6ed50fb5fe06004206886509211229740694b3ac17bec1ea59ce42c21d1566c15fbd65c5e5d90f6390409a02ecfa10309326f43
#[test]
fn decrypt_verify() {
    let scalar = NonZeroScalar::<Sm2>::try_from(PRIVATE_KEY.as_ref() as &[u8]).unwrap();

    let mut cipher = Vec::from(&CIPHER);

    assert_eq!(
        DecryptingKey::new_with_mode(scalar, sm2::pke::Mode::C1C2C3)
            .decrypt(&mut cipher)
            .unwrap(),
        MSG
    );
}

#[test]
fn decrypt_asna1_verify() {
    let scalar = NonZeroScalar::<Sm2>::try_from(PRIVATE_KEY.as_ref() as &[u8]).unwrap();

    let mut cipher = Vec::from(&ASN1_CIPHER);
    let dk = DecryptingKey::new_with_mode(scalar, sm2::pke::Mode::C1C2C3);
    println!("{:?}", dk);
    assert_eq!(dk.decrypt_asna1(&mut cipher).unwrap(), MSG);
}

#[test]
fn encrypt_and_decrpyt_asna1_test() {
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&PRIVATE_KEY.as_ref());
    let dk = if let Some(scalar) = Option::from(NonZeroScalar::new(scalar)) {
        DecryptingKey::from_nonzero_scalar(scalar).unwrap()
    } else {
        panic!("...")
    };
    let ek = dk.encrypting_key();
    println!("{:?}", dk);
    let cipher_bytes = ek.encrypt_asna1(MSG).unwrap();
    let ciphertext: String = cipher_bytes.iter().map(|x| format!("{:02x}", x)).collect();
    println!("{}", ciphertext);
    let dk_bytes = dk.as_nonzero_scalar().to_bytes();
    let sk = SecretKey::from_bytes(&dk_bytes).unwrap();
    let pem = sk.to_sec1_pem(sm2::pkcs8::LineEnding::LF).unwrap();
    println!("{}", (pem.as_ref() as &str));
    assert_eq!(dk.decrypt_asna1(&cipher_bytes).unwrap(), MSG);
}

prop_compose! {
    fn decrypting_key()(bytes in any::<[u8; 32]>()) -> DecryptingKey {
        loop {
            let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into());
            if let Some(scalar) = Option::from(NonZeroScalar::new(scalar)) {
                return DecryptingKey::from_nonzero_scalar(scalar).unwrap();
            }
        }
    }
}

prop_compose! {
    fn decrypting_key_c1c2c3()(bytes in any::<[u8; 32]>()) -> DecryptingKey {
        loop {
            let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into());
            if let Some(scalar) = Option::from(NonZeroScalar::new(scalar)) {
                return DecryptingKey::new_with_mode(scalar, sm2::pke::Mode::C1C2C3);
            }
        }
    }
}

proptest! {
    #[test]
    fn encrypt_and_decrpyt_asna1(dk in decrypting_key()) {
        let ek = dk.encrypting_key();
        let cipher_bytes = ek.encrypt_asna1(MSG).unwrap();
        let ciphertext : String = cipher_bytes.iter().map(|x| format!("{:02x}", x)).collect();
        let dk_bytes = dk.as_nonzero_scalar().to_bytes();
        let sk = SecretKey::from_bytes(&dk_bytes).unwrap();
        let pem = sk.to_sec1_pem(sm2::pkcs8::LineEnding::LF).unwrap();
        println!("{}", (pem.as_ref() as &str));
        println!("{:?}", dk);
        println!("{}", ciphertext);
        prop_assert!(dk.decrypt_asna1(&cipher_bytes).is_ok());
    }

    #[test]
    fn encrypt_and_decrpyt(dk in decrypting_key()) {
        let ek = dk.encrypting_key();
        let mut cipher_bytes = ek.encrypt(MSG).unwrap();
        assert_eq!(dk.decrypt(&mut cipher_bytes).unwrap(), MSG);
    }

    #[test]
    fn encrypt_and_decrpyt_mode(dk in decrypting_key_c1c2c3()) {
        let ek = dk.encrypting_key();
        let mut cipher_bytes = ek.encrypt(MSG).unwrap();
        assert_eq!(
            dk.decrypt(&mut cipher_bytes)
                .unwrap(),
            MSG
        );
    }
}
