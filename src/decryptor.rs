//! Methods to decrypt PGP messages

// https://docs.rs/sequoia-openpgp/0.21.0/sequoia_openpgp/parse/stream/struct.Decryptor.html

use crate::keys;
use openpgp::crypto::KeyPair;
use openpgp::parse::{stream::*, PacketParser, Parse};
use openpgp::types::SymmetricAlgorithm;
use openpgp::{
    packet::{Key, PKESK, SKESK},
    Cert, KeyID, Result,
};
use sequoia_openpgp as openpgp;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::Message;

pub fn decrypt(message: String, passphrase: Password) -> Result<String> {
    println!("Decryption method");
    // Load the certificate
    let mut private_cert = CertParser::from_bytes(keys::PRIVATE_KEY)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let mut public_cert = CertParser::from_bytes(keys::PUBLIC_KEY)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    private_cert.merge_public(public_cert);
    println!("Cert loaded");
    for ua in private_cert.userids() {
        println!("  {}", String::from_utf8_lossy(ua.value()));
    }

    let key = private_cert.primary_key().key().parts_as_secret()?;
    // Extract the keys using passphrase
    let mut keypair = key.clone().decrypt_secret(&passphrase)?.into_keypair()?;

    // Load the message as CipherText
    let msg = Ciphertext::from_bytes(message.as_bytes()).unwrap();
    let decrypted = keypair.decrypt(msg);

    //let decrypted = keypair.decrypt(msg);
    //println!("{}", decrypted);
    //Ok(format!("{}", decrypted))
    Ok(String::from(decrypted))
}
