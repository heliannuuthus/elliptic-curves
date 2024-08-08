#![cfg(feature = "pke")]

use elliptic_curve::{CurveArithmetic, NonZeroScalar};
use hex_literal::hex;
use sm2::{
    pke::{DecryptingKey, EncryptingKey},
    PublicKey, Sm2,
};

// sec1 public key b
const PUBLIC_KEY: [u8; 65] = hex!("044b0b5d9b5b13c62238c86ecb7161ce0831fb1a0f29441ddd212cecbad2eea0b99e792d0e2dcfc70555ac24b536d7476e99ba8562f75de5ce8f0595909138ec0c");
const PRIVATE_KEY: [u8; 32] =
    hex!("F7526C518958878A11D2F933F85DECFB3C51D8D170192C2CD1A4A2B69A1C92E0");
const MSG: &[u8] = b"plaintext";

// uncompress, starts with 04
const CIPHER: [u8; 106] = hex!("0437c84a1ee61a707cf5819b64a56f82186e69771775119c82139b6a56f5ff64fec5f3b1c5783648fc306be5a0a4e14c219bbecd62670bc8d8d0fe56d67e6baeff8ba118c7e79dc3abacbf1f4e13533081862158f720fd32705fc318f7f1f617a8734bbcc7569d0665e1");
// compressed starts with 03
// openssl pkeyutl -encrypt -in - -inkey sm2.key -out cipher.txt
const ASN1_CIPHER: [u8; 116] = hex!("3072022012872d1645ee63d49d801867e3ff8a4812358d062fe680e2bcf9d15a72b9b7c90220057f515f4c399dfff8eb979964c07057f1c9ca516ee11df4576bc08da98877ec04208cbbb21e95ad104f6e8fc04514e4be536dc5be53c9bb7da9177fafca40642ab5040a69e62a53a2e930fda314");

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
fn encrypt_and_decrpyt() {
    let mut ek = EncryptingKey::from_sec1_bytes(&PUBLIC_KEY).unwrap();
    let mut dk = DecryptingKey::from_bytes(&PRIVATE_KEY.into()).unwrap();
    let mut cipher_bytes = ek.encrypt(MSG).unwrap();
    assert_eq!(dk.decrypt(&mut cipher_bytes).unwrap(), MSG);
}

#[test]
fn encrypt_and_decrpyt_mode() {
    let mut cipher_bytes = EncryptingKey::new_with_mode(
        PublicKey::from_sec1_bytes(&PUBLIC_KEY).unwrap(),
        sm2::pke::Mode::C1C3C2,
    )
    .encrypt(MSG)
    .unwrap();
    let scalar: NonZeroScalar<sm2::Sm2> =
        NonZeroScalar::<sm2::Sm2>::try_from(PRIVATE_KEY.as_ref() as &[u8]).unwrap();
    assert_eq!(
        DecryptingKey::new_with_mode(scalar, sm2::pke::Mode::C1C3C2)
            .decrypt(&mut cipher_bytes)
            .unwrap(),
        MSG
    );
}
