// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use camino::Utf8Path;
use miette::{IntoDiagnostic, Result};
use x509_cert::{ext::pkix::certpolicy::PolicyInformation, spki::ObjectIdentifier};

use crate::ValidDocument;

#[derive(knus::Decode, Debug)]
pub struct Document {
    #[knus(children(name = "key-pair"))]
    pub key_pairs: Vec<KeyPair>,

    #[knus(children(name = "entity"))]
    pub entities: Vec<Entity>,

    #[knus(children(name = "certificate"))]
    pub certificates: Vec<Certificate>,

    #[knus(children(name = "certificate-request"))]
    pub certificate_requests: Vec<CertificateRequest>,

    #[knus(children(name = "certificate-list"))]
    pub certificate_lists: Vec<CertificateList>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct KeyPair {
    #[knus(argument)]
    pub name: String,
    #[knus(children)]
    pub key_type: Vec<KeyType>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa(RsaKeyConfig),
    P384,
    Ed25519,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct RsaKeyConfig {
    #[knus(property, default = 2048)]
    pub num_bits: usize,
    #[knus(property, default = 65537)]
    pub public_exponent: usize,
}

#[derive(knus::Decode, Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    #[knus(argument)]
    pub name: String,
    #[knus(child, unwrap(argument))]
    pub common_name: String,
    #[knus(children)]
    pub base_dn: Vec<EntityNameComponent>,
}

#[derive(knus::Decode, Debug, Clone, PartialEq, Eq)]
pub enum EntityNameComponent {
    CountryName(#[knus(argument)] String),
    StateOrProvinceName(#[knus(argument)] String),
    LocalityName(#[knus(argument)] String),
    OrganizationName(#[knus(argument)] String),
    OrganizationalUnitName(#[knus(argument)] String),
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct Certificate {
    #[knus(argument)]
    pub name: String,

    #[knus(child, unwrap(argument))]
    pub subject_entity: String,
    #[knus(child, unwrap(argument))]
    pub subject_key: String,

    #[knus(child, unwrap(argument))]
    pub issuer_entity: Option<String>,
    #[knus(child, unwrap(argument))]
    pub issuer_certificate: Option<String>,
    #[knus(child, unwrap(argument))]
    pub issuer_key: String,

    #[knus(child, unwrap(argument))]
    pub digest_algorithm: Option<DigestAlgorithm>,

    #[knus(child, unwrap(argument))]
    pub not_before: Option<String>,
    #[knus(child, unwrap(argument))]
    pub not_after: String,

    #[knus(child, unwrap(argument))]
    pub serial_number: String,

    #[knus(child, unwrap(children))]
    pub extensions: Option<Vec<X509Extensions>>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct CertificateRequest {
    #[knus(argument)]
    pub name: String,

    #[knus(child, unwrap(argument))]
    pub subject_entity: String,
    #[knus(child, unwrap(argument))]
    pub subject_key: String,
    #[knus(child, unwrap(argument))]
    pub digest_algorithm: Option<DigestAlgorithm>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct CertificateList {
    #[knus(argument)]
    pub name: String,

    #[knus(arguments)]
    pub certificates: Vec<String>,
}

#[derive(knus::DecodeScalar, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum DigestAlgorithm {
    Sha_256,
    Sha_384,
    Sha_512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
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

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct BasicConstraintsExtension {
    #[knus(property)]
    pub critical: bool,

    #[knus(property)]
    pub ca: bool,

    #[knus(property)]
    pub path_len: Option<u8>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct KeyUsageExtension {
    #[knus(property)]
    pub critical: bool,

    #[knus(child)]
    pub digital_signature: bool,

    #[knus(child)]
    pub non_repudiation: bool,

    #[knus(child)]
    pub key_encipherment: bool,

    #[knus(child)]
    pub data_encipherment: bool,

    #[knus(child)]
    pub key_agreement: bool,

    #[knus(child)]
    pub key_cert_sign: bool,

    #[knus(child)]
    pub crl_sign: bool,

    #[knus(child)]
    pub encipher_only: bool,

    #[knus(child)]
    pub decipher_only: bool,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct ExtendedKeyUsageExtension {
    #[knus(property)]
    pub critical: bool,

    #[knus(child)]
    pub id_kp_server_auth: bool,

    #[knus(child)]
    pub id_kp_client_auth: bool,

    #[knus(child)]
    pub id_kp_code_signing: bool,

    #[knus(child)]
    pub id_kp_email_protection: bool,

    #[knus(child)]
    pub id_kp_time_stamping: bool,

    #[knus(child)]
    pub id_kp_ocspsigning: bool,

    #[knus(children(name = "oid"), unwrap(argument))]
    pub oids: Vec<String>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct SubjectKeyIdentifierExtension {
    #[knus(property)]
    pub critical: bool,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct AuthorityKeyIdentifierExtension {
    #[knus(property)]
    pub critical: bool,

    #[knus(child)]
    pub key_id: bool,

    #[knus(child)]
    pub issuer: bool,
}

/// The `CertificatePolicy` enum represents the set of KDL nodes that `pki-playground` can map to
/// OIDs. Configs may also provide OIDs in their string forms using the `oid` node.
#[derive(knus::Decode, Debug, PartialEq, Eq)]
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
    Oid(#[knus(argument)] String),
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct DiceTcbInfoExtension {
    #[knus(property)]
    pub critical: bool,

    #[knus(child, unwrap(children(name = "fwid")))]
    pub fwid_list: Vec<Fwid>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct Fwid {
    #[knus(child, unwrap(argument))]
    pub digest_algorithm: DigestAlgorithm,

    #[knus(child, unwrap(argument))]
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

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct CertificatePoliciesExtension {
    #[knus(property)]
    pub critical: bool,

    #[knus(children)]
    pub policies: Vec<CertificatePolicy>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub enum GeneralName {
    IpAddr(#[knus(argument)] String),
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct SubjectAltNameExtension {
    #[knus(property)]
    pub critical: bool,

    #[knus(children)]
    pub names: Vec<GeneralName>,
}

#[derive(knus::Decode, Debug, PartialEq, Eq)]
pub struct NameConstraintsExtension {
    #[knus(property)]
    pub critical: bool,

    #[knus(child, unwrap(children))]
    pub permitted: Option<Vec<GeneralName>>,

    #[knus(child, unwrap(children))]
    pub excluded: Option<Vec<GeneralName>>,
}

pub fn load_and_validate(path: &Utf8Path) -> Result<ValidDocument> {
    let in_kdl = std::fs::read_to_string(path).into_diagnostic()?;
    let doc: Document = knus::parse(path.as_str(), &in_kdl)?;
    ValidDocument::validate(doc)
}
