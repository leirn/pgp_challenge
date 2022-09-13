//! Methods to decrypt PGP messages

// https://docs.rs/sequoia-openpgp/0.21.0/sequoia_openpgp/parse/stream/struct.Decryptor.html

use std::io::Read;
use sequoia_openpgp as openpgp;
use openpgp::crypto::SessionKey;
use openpgp::types::SymmetricAlgorithm;
use openpgp::{KeyID, Cert, Result, packet::{Key, PKESK, SKESK}};
use openpgp::parse::{Parse, stream::*};
use sequoia_openpgp::policy::StandardPolicy;

let p = &StandardPolicy::new();

// This fetches keys and computes the validity of the verification.
struct Helper {};
impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        Ok(Vec::new()) // Feed the Certs to the verifier here...
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        Ok(()) // Implement your verification policy here.
    }
}
impl DecryptionHelper for Helper {
    fn decrypt<D>(&mut self, _: &[PKESK], skesks: &[SKESK],
                  _sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D) -> Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        skesks[0].decrypt(&"streng geheim".into())
            .map(|(algo, session_key)| decrypt(algo, &session_key));
        Ok(None)
    }
}

pub fn decrypt(message: &str, passphrase: &str) -> &str {
  Ok(0)
  let h = Helper {};
  let mut v = DecryptorBuilder::from_bytes(&message[..])?
      .with_policy(p, None, h)?;

  let mut content = Vec::new();
  v.read_to_end(&mut content)?;
  content
}
