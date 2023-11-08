// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config;
use crate::KeyPair;

use const_oid::db::rfc8410::ID_ED_25519;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey};
use miette::{IntoDiagnostic, Result};
use zeroize::Zeroizing;

pub struct Ed25519KeyPair {
    name: String,
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    pub fn new(name: &str) -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        Ed25519KeyPair {
            name: name.into(),
            signing_key,
        }
    }

    pub fn from_pem(name: &str, s: &str) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_pem(s).into_diagnostic()?;

        Ok(Ed25519KeyPair {
            name: name.into(),
            signing_key,
        })
    }
}

impl KeyPair for Ed25519KeyPair {
    fn name(&self) -> &str {
        &self.name
    }

    fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        self.signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::CRLF)
            .into_diagnostic()
    }

    fn to_spki(&self) -> Result<spki::Document> {
        self.signing_key
            .verifying_key()
            .to_public_key_der()
            .into_diagnostic()
    }

    fn signature_algorithm(
        &self,
        digest: Option<&config::DigestAlgorithm>,
    ) -> Result<spki::AlgorithmIdentifierOwned> {
        validate_digest(digest)?;

        Ok(spki::AlgorithmIdentifierOwned {
            oid: ID_ED_25519,
            parameters: None,
        })
    }

    fn signature(
        &self,
        digest_config: Option<&config::DigestAlgorithm>,
        bytes: &[u8],
    ) -> Result<Vec<u8>> {
        validate_digest(digest_config)?;

        let signature: Signature = self.signing_key.try_sign(bytes).into_diagnostic()?;
        // ECDSA signatures in rfc5280 certificates are encoded per rfc5753.
        // They are the DER encoding of the r and s integers as a SEQUENCE.
        Ok(signature.to_vec())
    }
}

fn validate_digest(digest: Option<&config::DigestAlgorithm>) -> Result<()> {
    // any value for `digest` other than `None` or `Sha_512` is an error
    match digest.unwrap_or(&config::DigestAlgorithm::Sha_512) {
        config::DigestAlgorithm::Sha_512 => Ok(()),
        _ => Err(miette::miette!(
            "Invalid digest algorithm, use 'sha-512' or None"
        )),
    }
}
