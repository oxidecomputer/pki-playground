use miette::{IntoDiagnostic, Result};
use pkcs1::der::Encode;
use pkcs8::{
    der::{
        asn1::{SetOfVec, Utf8StringRef},
        AnyRef,
    },
    AlgorithmIdentifier, DecodePrivateKey, EncodePrivateKey, EncodePublicKey, SubjectPublicKeyInfo,
};
use rsa::{BigUint, PaddingScheme, PublicKeyParts, RsaPrivateKey};
use sha2::Digest;
use sha2::Sha256;
use x509_cert::{
    attr::AttributeTypeAndValue,
    name::{Name, RdnSequence, RelativeDistinguishedName},
};
use zeroize::Zeroizing;

pub mod config;

pub trait KeyPair {
    fn name(&self) -> &str;

    fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>>;

    fn to_spki(&self) -> Result<spki::Document>;

    fn signature_algorithm(&self, digest: &config::DigestAlgorithm) -> AlgorithmIdentifier;
    fn signature(&self, digest_config: &config::DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>>;
}

impl dyn KeyPair {
    pub fn new(config: &config::KeyPair) -> Result<Box<dyn KeyPair>> {
        match &config.key_type[0] {
            config::KeyType::Rsa(x) => RsaKeyPair::new(&config.name, &x),
        }
    }

    pub fn from_pem(config: &config::KeyPair, s: &str) -> Result<Box<dyn KeyPair>> {
        match &config.key_type[0] {
            config::KeyType::Rsa(x) => RsaKeyPair::from_pem(&config.name, &x, s),
        }
    }
}

pub struct RsaKeyPair {
    name: String,
    private_key: Zeroizing<rsa::RsaPrivateKey>,
}

impl RsaKeyPair {
    pub fn new(name: &str, config: &config::RsaKeyConfig) -> Result<Box<dyn KeyPair>> {
        let mut rng = rand::thread_rng();
        let private_key = Zeroizing::new(
            rsa::algorithms::generate_multi_prime_key_with_exp(
                &mut rng,
                config.num_primes,
                config.num_bits,
                &config.public_exponent.into(),
            )
            .into_diagnostic()?,
        );

        Ok(Box::new(RsaKeyPair {
            name: name.into(),
            private_key: private_key,
        }))
    }

    pub fn from_pem(
        name: &str,
        config: &config::RsaKeyConfig,
        s: &str,
    ) -> Result<Box<dyn KeyPair>> {
        let private_key = Zeroizing::new(RsaPrivateKey::from_pkcs8_pem(s).into_diagnostic()?);
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

        Ok(Box::new(Self {
            name: name.into(),
            private_key: private_key,
        }))
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
        self.private_key.to_public_key_der().into_diagnostic()
    }

    fn signature_algorithm(&self, digest: &config::DigestAlgorithm) -> AlgorithmIdentifier {
        match digest {
            config::DigestAlgorithm::Sha_256 => AlgorithmIdentifier {
                oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
                parameters: None,
            },
        }
    }

    fn signature(&self, digest_config: &config::DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
        match digest_config {
            config::DigestAlgorithm::Sha_256 => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);

                let padding = PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>();
                self.private_key
                    .sign(padding, &hasher.finalize())
                    .into_diagnostic()
            }
        }
    }
}

#[derive(Debug)]
pub struct Entity<'a> {
    name: String,
    distinguished_name: Name<'a>,
}

impl<'a> Entity<'a> {
    pub fn name(&'a self) -> &'a str {
        return &self.name;
    }

    pub fn distinguished_name(&'a self) -> &Name<'a> {
        return &self.distinguished_name;
    }
}

impl<'a> std::fmt::Display for Entity<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Entity: {} => {}", self.name, self.distinguished_name)
    }
}

impl<'a> TryFrom<&'a config::Entity> for Entity<'a> {
    type Error = miette::Error;

    fn try_from(value: &'a config::Entity) -> Result<Self, Self::Error> {
        let mut rdns = Vec::new();

        for base_dn_attr in &value.base_dn {
            let atv = match base_dn_attr {
                config::EntityNameComponent::CountryName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::CN,
                    value: AnyRef::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
                config::EntityNameComponent::StateOrProvinceName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::ST,
                    value: AnyRef::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
                config::EntityNameComponent::LocalityName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::L,
                    value: AnyRef::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
                config::EntityNameComponent::OrganizationalUnitName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::OU,
                    value: AnyRef::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
                config::EntityNameComponent::OrganizationName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::O,
                    value: AnyRef::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
            };

            rdns.push([atv]);
        }

        rdns.push([AttributeTypeAndValue {
            oid: const_oid::db::rfc4519::CN,
            value: AnyRef::from(Utf8StringRef::new(&value.common_name).into_diagnostic()?),
        }]);

        let mut brdns = RdnSequence::default();
        for rdn in rdns {
            let sofv = SetOfVec::try_from(rdn).into_diagnostic()?;
            brdns.0.push(RelativeDistinguishedName::from(sofv));
        }

        Ok(Self {
            name: value.name.clone(),
            distinguished_name: brdns,
        })
    }
}
