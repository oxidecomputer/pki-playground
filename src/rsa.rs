// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config;
use crate::KeyPair;

use digest::Digest;
use miette::{IntoDiagnostic, Result};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::{
    traits::{PublicKeyParts, SignatureScheme},
    BigUint, RsaPrivateKey,
};
use zeroize::Zeroizing;

pub struct RsaKeyPair {
    name: String,
    private_key: RsaPrivateKey,
}

impl RsaKeyPair {
    pub fn new(name: &str, config: &config::RsaKeyConfig) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new_with_exp(&mut rng, config.num_bits, &config.public_exponent.into())
                .into_diagnostic()?;

        Ok(RsaKeyPair {
            name: name.into(),
            private_key,
        })
    }

    pub fn from_pem(name: &str, config: &config::RsaKeyConfig, s: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(s).into_diagnostic()?;
        if private_key.size() * 8 != config.num_bits {
            miette::bail!(
                "PEM-encoded RSA private key has modulus size {} but config specifies {}",
                private_key.size(),
                config.num_bits
            )
        }

        if private_key.e() != &BigUint::from(config.public_exponent) {
            miette::bail!(
                "PEM-encoded RSA private key has public exponent {} but config specifies {}",
                private_key.e(),
                config.public_exponent
            )
        }

        Ok(Self {
            name: name.into(),
            private_key,
        })
    }
}

impl KeyPair for RsaKeyPair {
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
            .to_public_key()
            .to_public_key_der()
            .into_diagnostic()
    }

    fn signature_algorithm(
        &self,
        digest: Option<&config::DigestAlgorithm>,
    ) -> Result<spki::AlgorithmIdentifierOwned> {
        let digest = digest.ok_or(miette::miette!(
            "Rsa signatures require a hash algorithm and None provided."
        ))?;

        let alg_id = match digest {
            config::DigestAlgorithm::Sha_256 => spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
                parameters: None,
            },
            config::DigestAlgorithm::Sha_384 => spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION,
                parameters: None,
            },
            config::DigestAlgorithm::Sha_512 => spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION,
                parameters: None,
            },
            d => return Err(miette::miette!("Unsupported digest algorithm: {:?}", d)),
        };

        Ok(alg_id)
    }

    fn signature(
        &self,
        digest_config: Option<&config::DigestAlgorithm>,
        bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let digest_config = digest_config.ok_or(miette::miette!(
            "Rsa signatures require a hash algorithm and None provided."
        ))?;

        match digest_config {
            config::DigestAlgorithm::Sha_256 => {
                let hash = sha2::Sha256::new().chain_update(bytes).finalize();
                let signer = rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha256>();
                let mut rng = rand::thread_rng();
                signer
                    .sign(Some(&mut rng), &self.private_key, &hash)
                    .into_diagnostic()
            }
            config::DigestAlgorithm::Sha_384 => {
                let hash = sha2::Sha384::new().chain_update(bytes).finalize();
                let signer = rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha384>();
                let mut rng = rand::thread_rng();
                signer
                    .sign(Some(&mut rng), &self.private_key, &hash)
                    .into_diagnostic()
            }
            config::DigestAlgorithm::Sha_512 => {
                let hash = sha2::Sha512::new().chain_update(bytes).finalize();
                let signer = rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha512>();
                let mut rng = rand::thread_rng();
                signer
                    .sign(Some(&mut rng), &self.private_key, &hash)
                    .into_diagnostic()
            }
            d => Err(miette::miette!("Unsupported digest algorithm: {:?}", d)),
        }
    }
}
