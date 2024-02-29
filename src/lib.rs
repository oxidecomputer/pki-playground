// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use const_oid::{AssociatedOid, ObjectIdentifier};
use digest::Digest;
use flagset::FlagSet;
use miette::{IntoDiagnostic, Result};
use sha1::Sha1;
use x509_cert::{
    attr::AttributeTypeAndValue,
    der::{
        asn1::{PrintableStringRef, SetOfVec, Utf8StringRef},
        Decode as _, Encode as _,
    },
    ext::pkix::{certpolicy::PolicyInformation, BasicConstraints, KeyUsage},
    name::{Name, RdnSequence, RelativeDistinguishedName},
    Certificate, TbsCertificate,
};
use zeroize::Zeroizing;

use const_oid::db::rfc5912;

pub mod config;
pub mod ed25519;
pub mod p384;
pub mod rsa;

use crate::p384::P384KeyPair;
use crate::rsa::RsaKeyPair;
use ed25519::Ed25519KeyPair;

pub trait KeyPair {
    fn name(&self) -> &str;

    fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>>;

    fn to_spki(&self) -> Result<spki::Document>;

    fn signature_algorithm(
        &self,
        digest: Option<&config::DigestAlgorithm>,
    ) -> Result<spki::AlgorithmIdentifierOwned>;

    /// Sign the provided bytes using the associated KeyPair. NOTE: The
    /// Vec<u8> returned must be the BIT STRING expected by the rfc5280
    /// §4.1.1.3 signatureValue field.
    fn signature(
        &self,
        digest_config: Option<&config::DigestAlgorithm>,
        bytes: &[u8],
    ) -> Result<Vec<u8>>;
}

impl dyn KeyPair {
    pub fn new(config: &config::KeyPair) -> Result<Box<dyn KeyPair>> {
        match &config.key_type[0] {
            config::KeyType::Rsa(x) => Ok(Box::new(RsaKeyPair::new(&config.name, x)?)),
            config::KeyType::P384 => Ok(Box::new(P384KeyPair::new(&config.name)?)),
            config::KeyType::Ed25519 => Ok(Box::new(Ed25519KeyPair::new(&config.name))),
        }
    }

    pub fn from_pem(config: &config::KeyPair, s: &str) -> Result<Box<dyn KeyPair>> {
        match &config.key_type[0] {
            config::KeyType::Rsa(x) => Ok(Box::new(RsaKeyPair::from_pem(&config.name, x, s)?)),
            config::KeyType::P384 => Ok(Box::new(P384KeyPair::from_pem(&config.name, s)?)),
            config::KeyType::Ed25519 => Ok(Box::new(Ed25519KeyPair::from_pem(&config.name, s)?)),
        }
    }
}

#[derive(Debug)]
pub struct Entity {
    name: String,
    distinguished_name: Name,
}

impl<'a> Entity {
    pub fn name(&'a self) -> &'a str {
        &self.name
    }

    pub fn distinguished_name(&'a self) -> &Name {
        &self.distinguished_name
    }
}

impl std::fmt::Display for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "Entity: {} => {}", self.name, self.distinguished_name)
    }
}

impl<'a> TryFrom<&'a config::Entity> for Entity {
    type Error = miette::Error;

    fn try_from(value: &'a config::Entity) -> Result<Self, Self::Error> {
        let mut rdns = Vec::new();

        for base_dn_attr in &value.base_dn {
            let atv = match base_dn_attr {
                config::EntityNameComponent::CountryName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::COUNTRY_NAME,
                    value: x509_cert::der::Any::from(PrintableStringRef::new(x).into_diagnostic()?),
                },
                config::EntityNameComponent::StateOrProvinceName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::ST,
                    value: x509_cert::der::Any::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
                config::EntityNameComponent::LocalityName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::LOCALITY_NAME,
                    value: x509_cert::der::Any::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
                config::EntityNameComponent::OrganizationalUnitName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::ORGANIZATIONAL_UNIT_NAME,
                    value: x509_cert::der::Any::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
                config::EntityNameComponent::OrganizationName(x) => AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::ORGANIZATION_NAME,
                    value: x509_cert::der::Any::from(Utf8StringRef::new(x).into_diagnostic()?),
                },
            };

            rdns.push([atv]);
        }

        rdns.push([AttributeTypeAndValue {
            oid: const_oid::db::rfc4519::COMMON_NAME,
            value: x509_cert::der::Any::from(
                Utf8StringRef::new(&value.common_name).into_diagnostic()?,
            ),
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

pub trait Extension {
    fn oid(&self) -> ObjectIdentifier;

    fn is_critical(&self) -> bool;

    fn as_der(&self) -> &[u8];
}

impl dyn Extension {
    pub fn from_config(
        config: &config::X509Extensions,
        tbs_cert: &TbsCertificate,
        issuer_cert: Option<&Certificate>,
    ) -> Result<Box<dyn Extension>> {
        match config {
            config::X509Extensions::BasicConstraints(x) => {
                Ok(Box::new(BasicConstraintsExtension::from_config(x)?))
            }
            config::X509Extensions::KeyUsage(x) => Ok(Box::new(KeyUsageExtension::from_config(x)?)),
            config::X509Extensions::SubjectKeyIdentifier(x) => Ok(Box::new(
                SubjectKeyIdentifierExtension::from_config(x, tbs_cert)?,
            )),
            config::X509Extensions::AuthorityKeyIdentifier(x) => Ok(Box::new(
                AuthorityKeyIdentifierExtension::from_config(x, tbs_cert, issuer_cert)?,
            )),
            config::X509Extensions::ExtendedKeyUsage(x) => {
                Ok(Box::new(ExtendedKeyUsageExtension::from_config(x)?))
            }
            config::X509Extensions::CertificatePolicies(x) => {
                Ok(Box::new(CertificatePoliciesExtension::from_config(x)?))
            }
        }
    }
}

pub struct BasicConstraintsExtension {
    is_critical: bool,
    der: Vec<u8>,
}

impl BasicConstraintsExtension {
    pub fn from_config(config: &config::BasicConstraintsExtension) -> Result<Self> {
        let der = BasicConstraints {
            ca: config.ca,
            path_len_constraint: config.path_len,
        }
        .to_der()
        .into_diagnostic()?;

        Ok(BasicConstraintsExtension {
            is_critical: config.critical,
            der,
        })
    }
}

impl Extension for BasicConstraintsExtension {
    fn oid(&self) -> ObjectIdentifier {
        x509_cert::ext::pkix::BasicConstraints::OID
    }

    fn is_critical(&self) -> bool {
        self.is_critical
    }

    fn as_der(&self) -> &[u8] {
        &self.der
    }
}

pub struct KeyUsageExtension {
    is_critical: bool,
    der: Vec<u8>,
}

impl KeyUsageExtension {
    pub fn from_config(config: &config::KeyUsageExtension) -> Result<Self> {
        let mut key_usage_flags = FlagSet::default();
        if config.digital_signature {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::DigitalSignature
        }

        if config.non_repudiation {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::NonRepudiation
        }

        if config.key_encipherment {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::KeyEncipherment
        }

        if config.data_encipherment {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::DataEncipherment
        }

        if config.key_agreement {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::KeyAgreement
        }

        if config.key_cert_sign {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::KeyCertSign
        }

        if config.crl_sign {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::CRLSign
        }

        if config.encipher_only {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::EncipherOnly
        }

        if config.decipher_only {
            key_usage_flags |= x509_cert::ext::pkix::KeyUsages::DecipherOnly
        }

        let der = KeyUsage(key_usage_flags).to_der().into_diagnostic()?;

        Ok(KeyUsageExtension {
            is_critical: config.critical,
            der,
        })
    }
}

pub struct ExtendedKeyUsageExtension {
    is_critical: bool,
    der: Vec<u8>,
}

impl Extension for ExtendedKeyUsageExtension {
    fn oid(&self) -> ObjectIdentifier {
        x509_cert::ext::pkix::ExtendedKeyUsage::OID
    }

    fn is_critical(&self) -> bool {
        self.is_critical
    }

    fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl ExtendedKeyUsageExtension {
    pub(crate) fn from_config(config: &config::ExtendedKeyUsageExtension) -> Result<Self> {
        let mut extended_key_usage_oids = Vec::new();
        if config.id_kp_client_auth {
            extended_key_usage_oids.push(rfc5912::ID_KP_CLIENT_AUTH);
        }

        if config.id_kp_server_auth {
            extended_key_usage_oids.push(rfc5912::ID_KP_SERVER_AUTH);
        }

        if config.id_kp_code_signing {
            extended_key_usage_oids.push(rfc5912::ID_KP_CODE_SIGNING);
        }

        if config.id_kp_email_protection {
            extended_key_usage_oids.push(rfc5912::ID_KP_EMAIL_PROTECTION);
        }

        if config.id_kp_time_stamping {
            extended_key_usage_oids.push(rfc5912::ID_KP_TIME_STAMPING);
        }

        if config.id_kp_ocspsigning {
            extended_key_usage_oids.push(rfc5912::ID_KP_OCSP_SIGNING);
        }

        for oid in config.oids.iter() {
            extended_key_usage_oids.push(ObjectIdentifier::new(oid).into_diagnostic()?);
        }

        let ext_key_usage = x509_cert::ext::pkix::ExtendedKeyUsage(extended_key_usage_oids);

        Ok(ExtendedKeyUsageExtension {
            der: ext_key_usage.to_der().into_diagnostic()?,
            is_critical: config.critical,
        })
    }
}

impl Extension for KeyUsageExtension {
    fn oid(&self) -> ObjectIdentifier {
        x509_cert::ext::pkix::KeyUsage::OID
    }

    fn is_critical(&self) -> bool {
        self.is_critical
    }

    fn as_der(&self) -> &[u8] {
        &self.der
    }
}

pub struct SubjectKeyIdentifierExtension {
    is_critical: bool,
    der: Vec<u8>,
}

impl SubjectKeyIdentifierExtension {
    pub fn from_config(
        config: &config::SubjectKeyIdentifierExtension,
        tbs_cert: &TbsCertificate,
    ) -> Result<Self> {
        let subject_pub_key = tbs_cert
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap();

        let mut hasher = Sha1::new();
        hasher.update(subject_pub_key);
        let skid = hasher.finalize();

        let der = x509_cert::ext::pkix::SubjectKeyIdentifier(
            x509_cert::der::asn1::OctetString::new(&*skid).into_diagnostic()?,
        );
        Ok(SubjectKeyIdentifierExtension {
            is_critical: config.critical,
            der: der.to_der().into_diagnostic()?,
        })
    }
}

impl Extension for SubjectKeyIdentifierExtension {
    fn oid(&self) -> ObjectIdentifier {
        x509_cert::ext::pkix::SubjectKeyIdentifier::OID
    }

    fn is_critical(&self) -> bool {
        self.is_critical
    }

    fn as_der(&self) -> &[u8] {
        &self.der
    }
}

pub struct AuthorityKeyIdentifierExtension {
    is_critical: bool,
    der: Vec<u8>,
}

impl AuthorityKeyIdentifierExtension {
    pub fn from_config(
        config: &config::AuthorityKeyIdentifierExtension,
        _tbs_cert: &TbsCertificate,
        issuer_cert: Option<&Certificate>,
    ) -> Result<Self> {
        let mut authority_key_identifier = None;
        let mut authority_cert_issuer = None;
        let mut authority_cert_serial_number = None;

        let issuer_tbs = if let Some(issuer_cert) = issuer_cert {
            &issuer_cert.tbs_certificate
        } else if _tbs_cert.subject == _tbs_cert.issuer {
            _tbs_cert
        } else {
            return Err(miette::miette!(
                "Authority Key Identifier extension requested but no issuer certificate specified"
            ));
        };

        if config.issuer {
            authority_cert_issuer = Some(vec![
                x509_cert::ext::pkix::name::GeneralName::DirectoryName(issuer_tbs.subject.clone()),
            ]);
            authority_cert_serial_number = Some(issuer_tbs.serial_number.clone());
        }

        if config.key_id {
            if let Some(extensions) = &issuer_tbs.extensions {
                for extension in extensions {
                    if extension.extn_id == x509_cert::ext::pkix::SubjectKeyIdentifier::OID {
                        let ski = x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                            extension.extn_value.as_bytes(),
                        )
                        .into_diagnostic()?;
                        authority_key_identifier = Some(ski.0)
                    }
                }
            }

            if authority_key_identifier.is_none() {
                return Err(miette::miette!("Authority Key Identifier extension with key identifer requested but issuer certificate does not include a Subject Key Identifier extension"));
            }
        }

        let der = x509_cert::ext::pkix::AuthorityKeyIdentifier {
            key_identifier: authority_key_identifier,
            authority_cert_issuer,
            authority_cert_serial_number,
        }
        .to_der()
        .into_diagnostic()?;

        Ok(AuthorityKeyIdentifierExtension {
            is_critical: config.critical,
            der,
        })
    }
}

impl Extension for AuthorityKeyIdentifierExtension {
    fn oid(&self) -> ObjectIdentifier {
        x509_cert::ext::pkix::AuthorityKeyIdentifier::OID
    }

    fn is_critical(&self) -> bool {
        self.is_critical
    }

    fn as_der(&self) -> &[u8] {
        &self.der
    }
}

pub struct CertificatePoliciesExtension {
    is_critical: bool,
    der: Vec<u8>,
}

impl Extension for CertificatePoliciesExtension {
    fn oid(&self) -> ObjectIdentifier {
        x509_cert::ext::pkix::CertificatePolicies::OID
    }

    fn is_critical(&self) -> bool {
        self.is_critical
    }

    fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl CertificatePoliciesExtension {
    pub fn from_config(config: &config::CertificatePoliciesExtension) -> Result<Self> {
        let mut policies = Vec::new();

        for policy in &config.policies {
            policies.push(PolicyInformation::try_from(policy)?);
        }

        let der = x509_cert::ext::pkix::CertificatePolicies(policies)
            .to_der()
            .into_diagnostic()?;

        Ok(CertificatePoliciesExtension {
            is_critical: config.critical,
            der,
        })
    }
}
