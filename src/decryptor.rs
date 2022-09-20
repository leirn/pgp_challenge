//! Methods to decrypt PGP messages

// https://docs.rs/sequoia-openpgp/0.21.0/sequoia_openpgp/parse/stream/struct.Decryptor.html

use keys;
use openpgp::crypto::{KeyPair, SessionKey};
use openpgp::parse::{stream::*, Parse};
use openpgp::types::SymmetricAlgorithm;
use openpgp::{
    packet::{Key, PKESK, SKESK},
    Cert, KeyID, Result,
};
use sequoia_openpgp as openpgp;

pub fn decrypt(message: &str, passphrase: &str) -> Result<String> {
    // Load the certificate
    let ppr = packet::PacketParser::from_bytes(keys.PRIVATE_KEY)?;
    for cert in cert::CertParser::from(ppr) {
        match cert {
            Ok(cert) => {
                println!("Key: {}", cert.fingerprint());
                for ua in cert.userids() {
                    println!("  User ID: {}", ua.userid());
                }
            }
            Err(err) => {
                eprintln!("Error reading keyring: {}", err);
            }
        }
    }

    let key = cert.primary_key().key().parts_as_secret()?;
    // Extract the keys using passphrase
    let mut keypair = key.clone().decrypt_secret(passphrase)?.into_keypair()?;

    // Load the message as CipherText
    let msg = Ciphertext::parse(message);

    let decrypted = keypair.decrypt(msg);
    println!(decrypted);
    Ok(format!("{}", decrypted))
}
