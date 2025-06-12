// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashSet;

use miette::{IntoDiagnostic, Result};
use x509_cert::{ext::pkix::certpolicy::PolicyInformation, spki::ObjectIdentifier};

#[derive(knuffel::Decode, Debug)]
pub struct Document {
    #[knuffel(children(name = "key-pair"))]
    pub key_pairs: Vec<KeyPair>,

    #[knuffel(children(name = "entity"))]
    pub entities: Vec<Entity>,

    #[knuffel(children(name = "certificate"))]
    pub certificates: Vec<Certificate>,

    #[knuffel(children(name = "certificate-request"))]
    pub certificate_requests: Vec<CertificateRequest>,

    #[knuffel(children(name = "certificate-list"))]
    pub certificate_lists: Vec<CertificateList>,
}

#[derive(knuffel::Decode, Debug)]
pub struct KeyPair {
    #[knuffel(argument)]
    pub name: String,
    #[knuffel(children)]
    pub key_type: Vec<KeyType>,
}

#[derive(knuffel::Decode, Debug)]
pub enum KeyType {
    Rsa(RsaKeyConfig),
    P384,
    Ed25519,
}

#[derive(knuffel::Decode, Debug)]
pub struct RsaKeyConfig {
    #[knuffel(property, default = 2048)]
    pub num_bits: usize,
    #[knuffel(property, default = 65537)]
    pub public_exponent: usize,
}

#[derive(knuffel::Decode, Debug)]
pub struct Entity {
    #[knuffel(argument)]
    pub name: String,
    #[knuffel(child, unwrap(argument))]
    pub common_name: String,
    #[knuffel(children)]
    pub base_dn: Vec<EntityNameComponent>,
}

#[derive(knuffel::Decode, Debug)]
pub enum EntityNameComponent {
    CountryName(#[knuffel(argument)] String),
    StateOrProvinceName(#[knuffel(argument)] String),
    LocalityName(#[knuffel(argument)] String),
    OrganizationName(#[knuffel(argument)] String),
    OrganizationalUnitName(#[knuffel(argument)] String),
}

#[derive(knuffel::Decode, Debug)]
pub struct Certificate {
    #[knuffel(argument)]
    pub name: String,

    #[knuffel(child, unwrap(argument))]
    pub subject_entity: String,
    #[knuffel(child, unwrap(argument))]
    pub subject_key: String,

    #[knuffel(child, unwrap(argument))]
    pub issuer_entity: Option<String>,
    #[knuffel(child, unwrap(argument))]
    pub issuer_certificate: Option<String>,
    #[knuffel(child, unwrap(argument))]
    pub issuer_key: String,

    #[knuffel(child, unwrap(argument))]
    pub digest_algorithm: Option<DigestAlgorithm>,

    #[knuffel(child, unwrap(argument))]
    pub not_before: Option<String>,
    #[knuffel(child, unwrap(argument))]
    pub not_after: String,

    #[knuffel(child, unwrap(argument))]
    pub serial_number: String,

    #[knuffel(child, unwrap(children))]
    pub extensions: Option<Vec<X509Extensions>>,
}

#[derive(knuffel::Decode, Debug)]
pub struct CertificateRequest {
    #[knuffel(argument)]
    pub name: String,

    #[knuffel(child, unwrap(argument))]
    pub subject_entity: String,
    #[knuffel(child, unwrap(argument))]
    pub subject_key: String,
    #[knuffel(child, unwrap(argument))]
    pub digest_algorithm: Option<DigestAlgorithm>,
}

#[derive(knuffel::Decode, Debug)]
pub struct CertificateList {
    #[knuffel(argument)]
    pub name: String,

    #[knuffel(arguments)]
    pub certificates: Vec<String>,
}

#[derive(knuffel::DecodeScalar, Debug)]
#[allow(non_camel_case_types)]
pub enum DigestAlgorithm {
    Sha_256,
    Sha_384,
    Sha_512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

#[derive(knuffel::Decode, Debug)]
pub enum X509Extensions {
    BasicConstraints(BasicConstraintsExtension),
    KeyUsage(KeyUsageExtension),
    SubjectKeyIdentifier(SubjectKeyIdentifierExtension),
    AuthorityKeyIdentifier(AuthorityKeyIdentifierExtension),
    ExtendedKeyUsage(ExtendedKeyUsageExtension),
    CertificatePolicies(CertificatePoliciesExtension),
    DiceTcbInfo(DiceTcbInfoExtension),
    SubjectAltName(SubjectAltNameExtension),
    NameConstraints(NameConstraintsExtension),
}

#[derive(knuffel::Decode, Debug)]
pub struct BasicConstraintsExtension {
    #[knuffel(property)]
    pub critical: bool,

    #[knuffel(property)]
    pub ca: bool,

    #[knuffel(property)]
    pub path_len: Option<u8>,
}

#[derive(knuffel::Decode, Debug)]
pub struct KeyUsageExtension {
    #[knuffel(property)]
    pub critical: bool,

    #[knuffel(child)]
    pub digital_signature: bool,

    #[knuffel(child)]
    pub non_repudiation: bool,

    #[knuffel(child)]
    pub key_encipherment: bool,

    #[knuffel(child)]
    pub data_encipherment: bool,

    #[knuffel(child)]
    pub key_agreement: bool,

    #[knuffel(child)]
    pub key_cert_sign: bool,

    #[knuffel(child)]
    pub crl_sign: bool,

    #[knuffel(child)]
    pub encipher_only: bool,

    #[knuffel(child)]
    pub decipher_only: bool,
}

#[derive(knuffel::Decode, Debug)]
pub struct ExtendedKeyUsageExtension {
    #[knuffel(property)]
    pub critical: bool,

    #[knuffel(child)]
    pub id_kp_server_auth: bool,

    #[knuffel(child)]
    pub id_kp_client_auth: bool,

    #[knuffel(child)]
    pub id_kp_code_signing: bool,

    #[knuffel(child)]
    pub id_kp_email_protection: bool,

    #[knuffel(child)]
    pub id_kp_time_stamping: bool,

    #[knuffel(child)]
    pub id_kp_ocspsigning: bool,

    #[knuffel(children(name = "oid"), unwrap(argument))]
    pub oids: Vec<String>,
}

#[derive(knuffel::Decode, Debug)]
pub struct SubjectKeyIdentifierExtension {
    #[knuffel(property)]
    pub critical: bool,
}

#[derive(knuffel::Decode, Debug)]
pub struct AuthorityKeyIdentifierExtension {
    #[knuffel(property)]
    pub critical: bool,

    #[knuffel(child)]
    pub key_id: bool,

    #[knuffel(child)]
    pub issuer: bool,
}

/// The `CertificatePolicy` enum represents the set of KDL nodes that `pki-playground` can map to
/// OIDs. Configs may also provide OIDs in their string forms using the `oid` node.
#[derive(knuffel::Decode, Debug)]
pub enum CertificatePolicy {
    /// Initial attestation policy OID from [DICE Certificate
    /// Profiles](https://trustedcomputinggroup.org/resource/dice-certificate-profiles/) §5.1.5.3
    TcgDiceKpAttestInit,
    /// Local attestation policy OID from [DICE Certificate
    /// Profiles](https://trustedcomputinggroup.org/resource/dice-certificate-profiles/) §5.1.5.4
    TcgDiceKpAttestLoc,
    /// Initial assertion policy OID from [DICE Certificate
    /// Profiles](https://trustedcomputinggroup.org/resource/dice-certificate-profiles/) §5.1.5.5
    TcgDiceKpAssertInit,
    /// Local assertion policy OID from [DICE Certificate
    /// Profiles](https://trustedcomputinggroup.org/resource/dice-certificate-profiles/) §5.1.5.6
    TcgDiceKpAssertLoc,
    /// Embedded certificate authority (ECA) policy OID from [DICE Certificate
    /// Profiles](https://trustedcomputinggroup.org/resource/dice-certificate-profiles/) §5.1.5.7
    TcgDiceKpEca,
    /// Initial identity policy OID from [DICE Certificate
    /// Profiles](https://trustedcomputinggroup.org/resource/dice-certificate-profiles/) §5.1.5.1
    TcgDiceKpIdentityInit,
    /// Local identity policy OID from [DICE Certificate
    /// Profiles](https://trustedcomputinggroup.org/resource/dice-certificate-profiles/) §5.1.5.2
    TcgDiceKpIdentityLoc,
    /// Platform identity policy from [OANA x.509 certificate policy
    /// terms](https://github.com/oxidecomputer/oana#asn1-object-identifiers)
    OanaPlatformIdentity,
    /// RoT code signing development policy from [OANA x.509 certificate policy
    /// terms](https://github.com/oxidecomputer/oana#asn1-object-identifiers)
    OanaRotCodeSigningDevelopment,
    /// RoT code signing release policy from [OANA x.509 certificate policy
    /// terms](https://github.com/oxidecomputer/oana#asn1-object-identifiers)
    OanaRotCodeSigningRelease,
    /// `oid` node taking an OID string argument
    Oid(#[knuffel(argument)] String),
}

#[derive(knuffel::Decode, Debug)]
pub struct DiceTcbInfoExtension {
    #[knuffel(property)]
    pub critical: bool,

    #[knuffel(child, unwrap(children(name = "fwid")))]
    pub fwid_list: Vec<Fwid>,
}

#[derive(knuffel::Decode, Debug)]
pub struct Fwid {
    #[knuffel(child, unwrap(argument))]
    pub digest_algorithm: DigestAlgorithm,

    #[knuffel(child, unwrap(argument))]
    pub digest: String,
}

impl TryFrom<&CertificatePolicy> for PolicyInformation {
    type Error = miette::Error;

    /// Map `CertificatePolicy` variants to the appropriate `PolicyInformation` struct. This is
    /// required as part of our conversion from the KDL to the DER certificate encoding.
    fn try_from(value: &CertificatePolicy) -> Result<Self> {
        let oid = match value {
            CertificatePolicy::TcgDiceKpIdentityInit => {
                ObjectIdentifier::new("2.23.133.5.4.100.6").into_diagnostic()?
            }
            CertificatePolicy::TcgDiceKpIdentityLoc => {
                ObjectIdentifier::new("2.23.133.5.4.100.7").into_diagnostic()?
            }
            CertificatePolicy::TcgDiceKpAttestInit => {
                ObjectIdentifier::new("2.23.133.5.4.100.8").into_diagnostic()?
            }
            CertificatePolicy::TcgDiceKpAttestLoc => {
                ObjectIdentifier::new("2.23.133.5.4.100.9").into_diagnostic()?
            }
            CertificatePolicy::TcgDiceKpAssertInit => {
                ObjectIdentifier::new("2.23.133.5.4.100.10").into_diagnostic()?
            }
            CertificatePolicy::TcgDiceKpAssertLoc => {
                ObjectIdentifier::new("2.23.133.5.4.100.11").into_diagnostic()?
            }
            CertificatePolicy::TcgDiceKpEca => {
                ObjectIdentifier::new("2.23.133.5.4.100.12").into_diagnostic()?
            }
            CertificatePolicy::OanaRotCodeSigningRelease => {
                ObjectIdentifier::new("1.3.6.1.4.1.57551.1.1").into_diagnostic()?
            }
            CertificatePolicy::OanaRotCodeSigningDevelopment => {
                ObjectIdentifier::new("1.3.6.1.4.1.57551.1.2").into_diagnostic()?
            }
            CertificatePolicy::OanaPlatformIdentity => {
                ObjectIdentifier::new("1.3.6.1.4.1.57551.1.3").into_diagnostic()?
            }
            CertificatePolicy::Oid(s) => ObjectIdentifier::new(s).into_diagnostic()?,
        };

        Ok(PolicyInformation {
            policy_identifier: oid,
            policy_qualifiers: None,
        })
    }
}

#[derive(knuffel::Decode, Debug)]
pub struct CertificatePoliciesExtension {
    #[knuffel(property)]
    pub critical: bool,

    #[knuffel(children)]
    pub policies: Vec<CertificatePolicy>,
}

#[derive(knuffel::Decode, Debug)]
pub enum GeneralName {
    IpAddr(#[knuffel(argument)] String),
}

#[derive(knuffel::Decode, Debug)]
pub struct SubjectAltNameExtension {
    #[knuffel(property)]
    pub critical: bool,

    #[knuffel(children)]
    pub names: Vec<GeneralName>,
}

#[derive(knuffel::Decode, Debug)]
pub struct NameConstraintsExtension {
    #[knuffel(property)]
    pub critical: bool,

    #[knuffel(child, unwrap(children))]
    pub permitted: Option<Vec<GeneralName>>,

    #[knuffel(child, unwrap(children))]
    pub excluded: Option<Vec<GeneralName>>,
}

pub fn load_and_validate(path: &std::path::Path) -> Result<Document> {
    let in_kdl = std::fs::read_to_string(path).into_diagnostic()?;
    let doc: Document = knuffel::parse(&path.to_string_lossy(), &in_kdl)?;

    let mut kp_names: HashSet<&str> = HashSet::new();
    for kp in &doc.key_pairs {
        if kp.key_type.len() != 1 {
            miette::bail!(
                "key pairs must have exactly one key type. key pair \"{}\" has {}.",
                kp.name,
                kp.key_type.len()
            );
        }
        if !kp_names.insert(&kp.name) {
            miette::bail!(
                "key pairs must have unique names. \"{}\" is used more than once.",
                kp.name
            )
        }
    }

    let mut entity_names: HashSet<&str> = HashSet::new();
    for entity in &doc.entities {
        if !entity_names.insert(&entity.name) {
            miette::bail!(
                "entities must have unique names. \"{}\" is used more than once.",
                entity.name
            )
        }
    }

    // Certificates can name other certificates as their issuer so need to
    // gather all the names before checking validity.
    let mut cert_names: HashSet<&str> = HashSet::new();
    for cert in &doc.certificates {
        if !cert_names.insert(&cert.name) {
            miette::bail!(
                "certificates must have unique names. \"{}\" is used more than once.",
                cert.name
            )
        }
    }

    for cert in &doc.certificates {
        if !entity_names.contains(cert.subject_entity.as_str()) {
            miette::bail!(
                "certificate \"{}\" subject entity \"{}\" does not exist",
                cert.name,
                cert.subject_key
            )
        }

        if !kp_names.contains(cert.subject_key.as_str()) {
            miette::bail!(
                "certificate \"{}\" subject key pair \"{}\" does not exist",
                cert.name,
                cert.subject_key
            )
        }

        match (&cert.issuer_entity, &cert.issuer_certificate) {
            (None, None) => miette::bail!("certificate \"{}\" must specify either an issuer entity or certificate", cert.name),
            (Some(_), Some(_)) => miette::bail!("certificate \"{}\" specifies both an issuer entity and certificate.  Only one may be specified.", cert.name),
            (Some(entity), None) => {
                if !entity_names.contains(entity.as_str()) {
                    miette::bail!(
                        "certificate \"{}\" issuer entity \"{}\" does not exist",
                        cert.name,
                        cert.issuer_key
                    )
                }
            }
            (None, Some(cert_name)) => {
                if !cert_names.contains(cert_name.as_str()) {
                    miette::bail!(
                        "certificate \"{}\" issuer certificate \"{}\" does not exist",
                        cert.name,
                        cert.issuer_key
                    )
                }
            }
        }

        if !kp_names.contains(cert.issuer_key.as_str()) {
            miette::bail!(
                "certificate \"{}\" issuer key pair \"{}\" does not exist",
                cert.name,
                cert.issuer_key
            )
        }
    }

    let mut csr_names: HashSet<&str> = HashSet::new();
    for csr in &doc.certificate_requests {
        if !csr_names.insert(&csr.name) {
            miette::bail!(
                "certificate requests must have unique names. \"{}\" is used more than once.",
                csr.name
            )
        }
    }

    for csr in &doc.certificate_requests {
        if !entity_names.contains(csr.subject_entity.as_str()) {
            miette::bail!(
                "certificate request \"{}\" subject entity \"{}\" does not exist",
                csr.name,
                csr.subject_key
            )
        }

        if !kp_names.contains(csr.subject_key.as_str()) {
            miette::bail!(
                "certificate request \"{}\" subject key pair \"{}\" does not exist",
                csr.name,
                csr.subject_key
            )
        }
    }

    for certlist in &doc.certificate_lists {
        for cert in &certlist.certificates {
            if !cert_names.contains(cert.as_str()) {
                miette::bail!("certificate \"{}\" does not exist", cert,)
            }
        }
    }

    Ok(doc)
}
