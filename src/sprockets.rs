// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Convenience mechanisms for generating trust quorum cert chains for testing

use crate::{
    config::{
        AuthorityKeyIdentifierExtension, BasicConstraintsExtension, Certificate, CertificateList,
        CertificatePoliciesExtension, CertificatePolicy, DiceTcbInfoExtension, DigestAlgorithm,
        Document, Entity, EntityNameComponent, Fwid, KeyPair, KeyType, KeyUsageExtension,
        SubjectKeyIdentifierExtension, X509Extensions,
    },
    ValidDocument,
};

fn test_root() -> (KeyPair, Entity, Certificate) {
    let name = "test-root-a".to_string();
    (
        KeyPair {
            name: name.clone(),
            key_type: vec![KeyType::P384],
        },
        Entity {
            name: name.clone(),
            common_name: name.clone(),
            base_dn: vec![
                EntityNameComponent::CountryName("US".into()),
                EntityNameComponent::OrganizationName("Oxide Computer Company".into()),
            ],
        },
        Certificate {
            name: name.clone(),
            subject_entity: name.clone(),
            subject_key: name.clone(),
            issuer_entity: Some(name.clone()),
            issuer_key: name.clone(),
            issuer_certificate: None,
            digest_algorithm: Some(DigestAlgorithm::Sha_384),
            not_after: "9999-12-31T23:59:59Z".into(),
            not_before: None,
            serial_number: "00".into(),
            extensions: Some(vec![
                X509Extensions::SubjectKeyIdentifier(SubjectKeyIdentifierExtension {
                    critical: false,
                }),
                X509Extensions::BasicConstraints(BasicConstraintsExtension {
                    critical: true,
                    ca: true,
                    path_len: None,
                }),
                X509Extensions::KeyUsage(KeyUsageExtension {
                    critical: true,
                    key_cert_sign: true,
                    crl_sign: true,
                    digital_signature: false,
                    non_repudiation: false,
                    key_encipherment: false,
                    data_encipherment: false,
                    key_agreement: false,
                    encipher_only: false,
                    decipher_only: false,
                }),
                X509Extensions::CertificatePolicies(CertificatePoliciesExtension {
                    critical: true,
                    policies: vec![
                        CertificatePolicy::OanaPlatformIdentity,
                        CertificatePolicy::TcgDiceKpIdentityInit,
                        CertificatePolicy::TcgDiceKpAttestInit,
                        CertificatePolicy::TcgDiceKpEca,
                    ],
                }),
            ]),
        },
    )
}

fn test_signer() -> (KeyPair, Entity, Certificate) {
    let name = "test-signer-a1".to_string();
    let issuer = "test-root-a".to_string();
    (
        KeyPair {
            name: name.clone(),
            key_type: vec![KeyType::P384],
        },
        Entity {
            name: name.clone(),
            common_name: name.clone(),
            base_dn: vec![
                EntityNameComponent::CountryName("US".into()),
                EntityNameComponent::OrganizationName("Oxide Computer Company".into()),
            ],
        },
        Certificate {
            name: name.clone(),
            subject_entity: name.clone(),
            subject_key: name.clone(),
            issuer_entity: None,
            issuer_key: issuer.clone(),
            issuer_certificate: Some(issuer.clone()),
            digest_algorithm: Some(DigestAlgorithm::Sha_384),
            not_after: "9999-12-31T23:59:59Z".into(),
            not_before: None,
            serial_number: "01".into(),
            extensions: Some(vec![
                X509Extensions::SubjectKeyIdentifier(SubjectKeyIdentifierExtension {
                    critical: false,
                }),
                X509Extensions::AuthorityKeyIdentifier(AuthorityKeyIdentifierExtension {
                    critical: false,
                    key_id: true,
                    issuer: false,
                }),
                X509Extensions::BasicConstraints(BasicConstraintsExtension {
                    critical: true,
                    ca: true,
                    path_len: None,
                }),
                X509Extensions::KeyUsage(KeyUsageExtension {
                    critical: true,
                    key_cert_sign: true,
                    crl_sign: true,
                    digital_signature: false,
                    non_repudiation: false,
                    key_encipherment: false,
                    data_encipherment: false,
                    key_agreement: false,
                    encipher_only: false,
                    decipher_only: false,
                }),
                X509Extensions::CertificatePolicies(CertificatePoliciesExtension {
                    critical: true,
                    policies: vec![
                        CertificatePolicy::OanaPlatformIdentity,
                        CertificatePolicy::TcgDiceKpIdentityInit,
                        CertificatePolicy::TcgDiceKpAttestInit,
                        CertificatePolicy::TcgDiceKpEca,
                    ],
                }),
            ]),
        },
    )
}

fn test_platformid(n: usize) -> (KeyPair, Entity, Certificate) {
    let name = format!("test-platformid-{n}");
    let issuer = "test-signer-a1".to_string();
    (
        KeyPair {
            name: name.clone(),
            key_type: vec![KeyType::Ed25519],
        },
        Entity {
            name: name.clone(),
            common_name: format!("PDV2:PPP-PPPPPPP:RRR:{n}"),
            base_dn: vec![
                EntityNameComponent::CountryName("US".into()),
                EntityNameComponent::OrganizationName("Oxide Computer Company".into()),
            ],
        },
        Certificate {
            name: name.clone(),
            subject_entity: name.clone(),
            subject_key: name.clone(),
            issuer_entity: None,
            issuer_key: issuer.clone(),
            issuer_certificate: Some(issuer.clone()),
            digest_algorithm: Some(DigestAlgorithm::Sha_384),
            not_after: "9999-12-31T23:59:59Z".into(),
            not_before: None,
            // We shouldn't be generating more than 1k platform IDs per test
            serial_number: (1000 + n).to_string(),
            extensions: Some(vec![
                X509Extensions::SubjectKeyIdentifier(SubjectKeyIdentifierExtension {
                    critical: false,
                }),
                X509Extensions::AuthorityKeyIdentifier(AuthorityKeyIdentifierExtension {
                    critical: false,
                    key_id: true,
                    issuer: false,
                }),
                X509Extensions::BasicConstraints(BasicConstraintsExtension {
                    critical: true,
                    ca: true,
                    path_len: None,
                }),
                X509Extensions::KeyUsage(KeyUsageExtension {
                    critical: true,
                    key_cert_sign: true,
                    crl_sign: true,
                    digital_signature: false,
                    non_repudiation: false,
                    key_encipherment: false,
                    data_encipherment: false,
                    key_agreement: false,
                    encipher_only: false,
                    decipher_only: false,
                }),
                X509Extensions::CertificatePolicies(CertificatePoliciesExtension {
                    critical: true,
                    policies: vec![
                        CertificatePolicy::OanaPlatformIdentity,
                        CertificatePolicy::TcgDiceKpIdentityInit,
                        CertificatePolicy::TcgDiceKpAttestInit,
                        CertificatePolicy::TcgDiceKpEca,
                    ],
                }),
            ]),
        },
    )
}

fn test_deviceid(n: usize) -> (KeyPair, Entity, Certificate) {
    let name = format!("test-deviceid-{n}");
    let issuer = format!("test-platformid-{n}");
    (
        KeyPair {
            name: name.clone(),
            key_type: vec![KeyType::Ed25519],
        },
        Entity {
            name: name.clone(),
            common_name: name.clone(),
            base_dn: vec![
                EntityNameComponent::CountryName("US".into()),
                EntityNameComponent::OrganizationName("Oxide Computer Company".into()),
            ],
        },
        Certificate {
            name: name.clone(),
            subject_entity: name.clone(),
            subject_key: name.clone(),
            issuer_entity: None,
            issuer_key: issuer.clone(),
            issuer_certificate: Some(issuer.clone()),
            digest_algorithm: Some(DigestAlgorithm::Sha_512),
            not_after: "9999-12-31T23:59:59Z".into(),
            not_before: None,
            // We shouldn't be generating more than 1k device IDs per test
            serial_number: (2000 + n).to_string(),
            extensions: Some(vec![
                X509Extensions::SubjectKeyIdentifier(SubjectKeyIdentifierExtension {
                    critical: false,
                }),
                X509Extensions::AuthorityKeyIdentifier(AuthorityKeyIdentifierExtension {
                    critical: false,
                    key_id: true,
                    issuer: false,
                }),
                X509Extensions::BasicConstraints(BasicConstraintsExtension {
                    critical: true,
                    ca: true,
                    path_len: None,
                }),
                X509Extensions::KeyUsage(KeyUsageExtension {
                    critical: true,
                    key_cert_sign: true,
                    crl_sign: true,
                    digital_signature: false,
                    non_repudiation: false,
                    key_encipherment: false,
                    data_encipherment: false,
                    key_agreement: false,
                    encipher_only: false,
                    decipher_only: false,
                }),
                X509Extensions::CertificatePolicies(CertificatePoliciesExtension {
                    critical: true,
                    policies: vec![
                        CertificatePolicy::OanaPlatformIdentity,
                        CertificatePolicy::TcgDiceKpIdentityInit,
                        CertificatePolicy::TcgDiceKpAttestInit,
                        CertificatePolicy::TcgDiceKpEca,
                    ],
                }),
            ]),
        },
    )
}

fn test_sprockets_auth(n: usize) -> (KeyPair, Entity, Certificate) {
    let name = format!("test-sprockets-auth-{n}");
    let issuer = format!("test-deviceid-{n}");
    (
        KeyPair {
            name: name.clone(),
            key_type: vec![KeyType::Ed25519],
        },
        Entity {
            name: name.clone(),
            common_name: name.clone(),
            base_dn: vec![
                EntityNameComponent::CountryName("US".into()),
                EntityNameComponent::OrganizationName("Oxide Computer Company".into()),
            ],
        },
        Certificate {
            name: name.clone(),
            subject_entity: name.clone(),
            subject_key: name.clone(),
            issuer_entity: None,
            issuer_key: issuer.clone(),
            issuer_certificate: Some(issuer.clone()),
            digest_algorithm: Some(DigestAlgorithm::Sha_512),
            not_after: "9999-12-31T23:59:59Z".into(),
            not_before: None,
            // We shouldn't be generating more than 1k sprockets auth keys per test
            serial_number: (3000 + n).to_string(),
            extensions: Some(vec![
                X509Extensions::SubjectKeyIdentifier(SubjectKeyIdentifierExtension {
                    critical: false,
                }),
                X509Extensions::AuthorityKeyIdentifier(AuthorityKeyIdentifierExtension {
                    critical: false,
                    key_id: true,
                    issuer: false,
                }),
                X509Extensions::BasicConstraints(BasicConstraintsExtension {
                    critical: true,
                    ca: false,
                    path_len: None,
                }),
                X509Extensions::KeyUsage(KeyUsageExtension {
                    critical: true,
                    key_cert_sign: false,
                    crl_sign: false,
                    digital_signature: true,
                    non_repudiation: true,
                    key_encipherment: false,
                    data_encipherment: false,
                    key_agreement: false,
                    encipher_only: false,
                    decipher_only: false,
                }),
                X509Extensions::CertificatePolicies(CertificatePoliciesExtension {
                    critical: true,
                    policies: vec![
                        CertificatePolicy::OanaPlatformIdentity,
                        CertificatePolicy::TcgDiceKpIdentityInit,
                        CertificatePolicy::TcgDiceKpAttestInit,
                        CertificatePolicy::TcgDiceKpEca,
                    ],
                }),
            ]),
        },
    )
}

fn test_sprockets_auth_certificate_list(n: usize) -> CertificateList {
    let name = format!("test-sprockets-auth-{n}");
    CertificateList {
        name: name.clone(),
        certificates: vec![
            name,
            format!("test-deviceid-{n}"),
            format!("test-platformid-{n}"),
            format!("test-signer-a1"),
        ],
    }
}

fn test_alias(n: usize) -> (KeyPair, Entity, Certificate) {
    let name = format!("test-alias-{n}");
    let issuer = format!("test-deviceid-{n}");
    (
        KeyPair {
            name: name.clone(),
            key_type: vec![KeyType::Ed25519],
        },
        Entity {
            name: name.clone(),
            common_name: "alias".to_string(),
            base_dn: vec![
                EntityNameComponent::CountryName("US".into()),
                EntityNameComponent::OrganizationName("Oxide Computer Company".into()),
            ],
        },
        Certificate {
            name: name.clone(),
            subject_entity: name.clone(),
            subject_key: name.clone(),
            issuer_entity: None,
            issuer_key: issuer.clone(),
            issuer_certificate: Some(issuer.clone()),
            digest_algorithm: None,
            not_after: "9999-12-31T23:59:59Z".into(),
            not_before: None,
            // We shouldn't be generating more than 1k sprockets auth keys per test
            serial_number: "00".to_string(),
            extensions: Some(vec![
                X509Extensions::BasicConstraints(BasicConstraintsExtension {
                    critical: true,
                    ca: false,
                    path_len: None,
                }),
                X509Extensions::KeyUsage(KeyUsageExtension {
                    critical: true,
                    key_cert_sign: false,
                    crl_sign: false,
                    digital_signature: true,
                    non_repudiation: false,
                    key_encipherment: false,
                    data_encipherment: false,
                    key_agreement: false,
                    encipher_only: false,
                    decipher_only: false,
                }),
                X509Extensions::CertificatePolicies(CertificatePoliciesExtension {
                    critical: true,
                    policies: vec![CertificatePolicy::TcgDiceKpAttestInit],
                }),
                X509Extensions::DiceTcbInfo(DiceTcbInfoExtension {
                    critical: true,
                    fwid_list: vec![Fwid {
                        digest_algorithm: DigestAlgorithm::Sha3_256,
                        digest: "72fa8f8ea84a42251031366002cbb36281d0131f78cd680436116a720cdd9de5"
                            .to_string(),
                    }],
                }),
            ]),
        },
    )
}

fn test_alias_certificate_list(n: usize) -> CertificateList {
    let name = format!("test-alias-{n}");
    CertificateList {
        name: name.clone(),
        certificates: vec![
            name,
            format!("test-deviceid-{n}"),
            format!("test-platformid-{n}"),
            format!("test-signer-a1"),
        ],
    }
}

pub fn generate_config(num_nodes: usize) -> ValidDocument {
    let root = test_root();
    let signer = test_signer();
    let mut doc = Document {
        key_pairs: vec![root.0, signer.0],
        entities: vec![root.1, signer.1],
        certificates: vec![root.2, signer.2],
        certificate_requests: vec![],
        certificate_lists: vec![],
    };
    for i in 1..=num_nodes {
        let platformid = test_platformid(i);
        let device_id = test_deviceid(i);
        let sprockets_auth = test_sprockets_auth(i);
        let alias = test_alias(i);

        doc.key_pairs.push(platformid.0);
        doc.key_pairs.push(device_id.0);
        doc.key_pairs.push(sprockets_auth.0);
        doc.key_pairs.push(alias.0);

        doc.entities.push(platformid.1);
        doc.entities.push(device_id.1);
        doc.entities.push(sprockets_auth.1);
        doc.entities.push(alias.1);

        doc.certificates.push(platformid.2);
        doc.certificates.push(device_id.2);
        doc.certificates.push(sprockets_auth.2);
        doc.certificates.push(alias.2);

        doc.certificate_lists
            .push(test_sprockets_auth_certificate_list(i));
        doc.certificate_lists.push(test_alias_certificate_list(i));
    }

    ValidDocument::validate(doc).expect("validation succeeds")
}

#[cfg(test)]
mod tests {
    use super::generate_config;
    use crate::config;
    use camino::Utf8PathBuf;
    use pretty_assertions::assert_eq;

    #[test]
    pub fn sprockets_example_matches_code_based_generation() {
        let path = Utf8PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/sprockets/config.kdl"
        ));

        let loaded = config::load_and_validate(&path).expect("config loads and validates");
        let generated = generate_config(2);

        assert_eq!(loaded, generated);
    }
}
