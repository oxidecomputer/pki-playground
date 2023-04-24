// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config;
use crate::KeyPair;

use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey};
use miette::{IntoDiagnostic, Result};
use zeroize::Zeroizing;

// Local constant for Ed25519 signature OID. We sent a patch upstream to get
// OIDs from RFD 8410 into the const-oid crate but it hasn't made it into a
// release yet (as of const-oid v0.9.2).
pub const ID_ED_25519: crate::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.101.112");

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
        digest: &config::DigestAlgorithm,
    ) -> Result<spki::AlgorithmIdentifierOwned> {
        validate_digest(digest)?;

        Ok(spki::AlgorithmIdentifierOwned {
            oid: ID_ED_25519,
            parameters: None,
        })
    }

    fn signature(&self, digest_config: &config::DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
        validate_digest(digest_config)?;

        let signature: Signature = self.signing_key.try_sign(bytes).into_diagnostic()?;
        // ECDSA signatures in rfc5280 certificates are encoded per rfc5753.
        // They are the DER encoding of the r and s integers as a SEQUENCE.
        Ok(signature.to_vec())
    }
}

fn validate_digest(digest: &config::DigestAlgorithm) -> Result<()> {
    // Any value for `digest` other than `Sha_512` is an error.
    match digest {
        config::DigestAlgorithm::Sha_512 => Ok(()),
        _ => Err(miette::miette!(
            "Invalid digest algorithm, ed25519 signatures require 'sha-512'"
        )),
    }
}
