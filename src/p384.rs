// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config;
use crate::KeyPair;
use digest::Digest;
use miette::{IntoDiagnostic, Result};
use p384::{
    ecdsa::{Signature, SigningKey},
    SecretKey,
};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use signature::{hazmat::PrehashSigner, SignatureEncoding};
use zeroize::Zeroizing;

pub struct P384KeyPair {
    name: String,
    private_key: SecretKey,
}

impl P384KeyPair {
    pub fn new(name: &str) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private_key = SecretKey::random(&mut rng);

        Ok(P384KeyPair {
            name: name.into(),
            private_key,
        })
    }

    pub fn from_pem(name: &str, s: &str) -> Result<Self> {
        let private_key = SecretKey::from_pkcs8_pem(s).into_diagnostic()?;
        Ok(P384KeyPair {
            name: name.into(),
            private_key,
        })
    }
}

impl KeyPair for P384KeyPair {
    fn name(&self) -> &str {
        &self.name
    }

    fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        self.private_key
            .to_pkcs8_pem(pkcs8::LineEnding::CRLF)
            .into_diagnostic()
    }

    fn to_spki(&self) -> Result<spki::Document> {
        self.private_key
            .public_key()
            .to_public_key_der()
            .into_diagnostic()
    }

    fn signature_algorithm(
        &self,
        digest: Option<&config::DigestAlgorithm>,
    ) -> Result<spki::AlgorithmIdentifierOwned> {
        let digest = digest.ok_or(miette::miette!(
            "P384 signatures require a hash algorithm but `None` provided."
        ))?;

        let alg_id = match digest {
            config::DigestAlgorithm::Sha_256 => spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            config::DigestAlgorithm::Sha_384 => spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_384,
                parameters: None,
            },
            config::DigestAlgorithm::Sha_512 => spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_512,
                parameters: None,
            },
        };

        Ok(alg_id)
    }

    fn signature(
        &self,
        digest_config: Option<&config::DigestAlgorithm>,
        bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let digest_config = digest_config.ok_or(miette::miette!(
            "P384 signatures require a hash algorithm but `None` provided."
        ))?;

        let signer: SigningKey = self.private_key.clone().into();

        let signature: Signature = match digest_config {
            config::DigestAlgorithm::Sha_256 => {
                let digest = sha2::Sha256::digest(bytes);
                signer.sign_prehash(&digest).into_diagnostic()?
            }
            config::DigestAlgorithm::Sha_384 => {
                let digest = sha2::Sha384::digest(bytes);
                signer.sign_prehash(&digest).into_diagnostic()?
            }
            config::DigestAlgorithm::Sha_512 => {
                let digest = sha2::Sha512::digest(bytes);
                signer.sign_prehash(&digest).into_diagnostic()?
            }
        };

        // ECDSA signatures in rfc5280 certificates are encoded per rfc5753.
        // They are the DER encoding of the r and s integers as a SEQUENCE.
        Ok(signature.to_der().to_vec())
    }
}
