// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{Entity, Extension, KeyPair};
use camino::Utf8PathBuf;
use clap::ValueEnum;
use miette::{miette, Context, IntoDiagnostic, Result};
use pem_rfc7468::LineEnding;
use spki::SubjectPublicKeyInfo;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::str::FromStr;
use std::time::SystemTime;
use x509_cert::{
    attr::Attributes,
    der::{
        asn1::{BitString, GeneralizedTime, UtcTime},
        DateTime, Decode, DecodePem, Encode, EncodePem,
    },
    request::{CertReq, CertReqInfo},
    time::Validity,
    Certificate, TbsCertificate,
};

use crate::config;

/// An identical structure to `Document` that has already been validated.
///
/// Importantly, this type does not derive knuffel types, because it
/// isn't ever read from the KDL directly. It can only be created by the
/// `validate_document` function.
///
/// In order to prevent mutation, all fields on a `ValidDocument` are private.
///
/// https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/
#[derive(Debug, PartialEq, Eq)]
pub struct ValidDocument {
    key_pairs: Vec<config::KeyPair>,
    entities: Vec<config::Entity>,
    certificates: Vec<config::Certificate>,
    certificate_requests: Vec<config::CertificateRequest>,
    certificate_lists: Vec<config::CertificateList>,
}

impl ValidDocument {
    pub fn write_key_pairs(&self, dir: Utf8PathBuf, opts: OutputFileExistsBehavior) -> Result<()> {
        for kp_config in &self.key_pairs {
            let kp = <dyn KeyPair>::new(kp_config)?;
            let kp_filename = format!("{}.key.pem", kp_config.name);
            let path = dir.join(&kp_filename);
            println!("Writing key pair to \"{}\"", &path);
            write_to_file(&path, kp.to_pkcs8_pem()?.as_bytes(), opts)?
        }
        Ok(())
    }

    pub fn write_certificate_lists(
        &self,
        dir: Utf8PathBuf,
        opts: OutputFileExistsBehavior,
    ) -> Result<()> {
        let certificates = self.load_certificates(dir.clone())?;
        for certlist_cfg in &self.certificate_lists {
            let mut cert_chain = String::new();
            let certlist_filename = format!("{}.certlist.pem", certlist_cfg.name);
            let path = dir.join(&certlist_filename);
            println!("Writing pki path to \"{}\"", &path);
            for cert_name in &certlist_cfg.certificates {
                let cert = certificates.get(cert_name).ok_or(miette!(
                    "Certificate does not exist: {}",
                    &certlist_cfg.name
                ))?;
                cert_chain += &cert.to_pem(LineEnding::CRLF).into_diagnostic()?;
            }
            write_to_file(&path, cert_chain.as_bytes(), opts)?
        }
        Ok(())
    }

    pub fn write_certificate_requests(
        &self,
        dir: Utf8PathBuf,
        opts: OutputFileExistsBehavior,
    ) -> Result<()> {
        let key_pairs = self.load_keypairs(dir.clone())?;
        let entities = self.load_entities()?;

        for csr_config in &self.certificate_requests {
            let subject_kp = key_pairs.get(&csr_config.subject_key).ok_or(miette!(
                "Subject key does not exist: {}",
                &csr_config.subject_key
            ))?;
            let public_key = SubjectPublicKeyInfo::from_der(subject_kp.to_spki()?.as_bytes())
                .into_diagnostic()?;

            let subject = entities.get(&csr_config.subject_entity).ok_or(miette!(
                "Entity does not exist: {}",
                &csr_config.subject_entity
            ))?;
            let subject = subject.distinguished_name().clone();

            let info = CertReqInfo {
                version: x509_cert::request::Version::V1,
                subject,
                public_key,
                attributes: Attributes::default(),
            };
            let info_der = info.to_der().into_diagnostic()?;

            let signature = subject_kp
                .signature(csr_config.digest_algorithm.as_ref(), &info_der)
                .wrap_err("Failed to sign CSR info structure")?;
            let signature = BitString::from_bytes(&signature).into_diagnostic()?;

            let algorithm = csr_config.digest_algorithm.as_ref();
            let algorithm = subject_kp.signature_algorithm(algorithm)?;

            let csr = CertReq {
                info,
                algorithm,
                signature,
            };

            let csr_filename = format!("{}.csr.pem", csr_config.name);
            let path = dir.join(&csr_filename);
            println!("Writing certificate request to \"{}\"", &path);
            write_to_file(
                &path,
                csr.to_pem(LineEnding::CRLF).into_diagnostic()?.as_bytes(),
                opts,
            )?
        }

        Ok(())
    }

    pub fn write_certificates(
        &self,
        dir: Utf8PathBuf,
        opts: OutputFileExistsBehavior,
    ) -> Result<()> {
        let key_pairs = self.load_keypairs(dir.clone())?;
        let entities = self.load_entities()?;

        for cert_config in &self.certificates {
            let subject_entity = entities.get(&cert_config.subject_entity).ok_or(miette!(
                "Subject entity for certificate {} does not exist: {}",
                &cert_config.name,
                &cert_config.subject_entity,
            ))?;
            let subject_kp = key_pairs.get(&cert_config.subject_key).ok_or(miette!(
                "Subject key pair for certificate {} does not exist: {}",
                &cert_config.name,
                &cert_config.subject_key,
            ))?;

            let issuer_cert_pem = if let Some(issuer_cert_name) = &cert_config.issuer_certificate {
                let issuer_cert_filename = format!("{}.cert.pem", issuer_cert_name);
                let path = dir.join(&issuer_cert_filename);

                let mut issuer_cert_pem = Vec::new();
                let mut issuer_cert_file =
                    std::fs::File::open(&path)
                        .into_diagnostic()
                        .wrap_err(format!(
                            "Unable to load issuer certificate \"{}\" from file \"{}\"",
                            issuer_cert_name, path
                        ))?;
                issuer_cert_file
                    .read_to_end(&mut issuer_cert_pem)
                    .into_diagnostic()?;
                Some(issuer_cert_pem)
            } else {
                None
            };

            let issuer_cert = if let Some(issuer_cert_pem) = &issuer_cert_pem {
                Some(x509_cert::Certificate::from_pem(issuer_cert_pem).into_diagnostic()?)
            } else {
                None
            };

            let issuer_dn = if let Some(issuer_cert) = &issuer_cert {
                issuer_cert.tbs_certificate.subject.clone()
            } else {
                entities
                    .get(cert_config.issuer_entity.as_ref().unwrap())
                    .unwrap()
                    .distinguished_name()
                    .clone()
            };

            let issuer_kp = key_pairs.get(&cert_config.issuer_key).ok_or(miette!(
                "Issuer key does not exist: {}",
                &cert_config.issuer_key
            ))?;

            let not_after = DateTime::from_str(&cert_config.not_after).into_diagnostic()?;
            let not_after = if not_after.year() >= 2050 {
                GeneralizedTime::from(not_after).into()
            } else {
                UtcTime::try_from(not_after).into_diagnostic()?.into()
            };
            let not_before = match &cert_config.not_before {
                None => DateTime::from_system_time(SystemTime::now()).into_diagnostic()?,
                Some(x) => DateTime::from_str(x).into_diagnostic()?,
            };
            let not_before = if not_before.year() >= 2050 {
                GeneralizedTime::from(not_before).into()
            } else {
                UtcTime::try_from(not_before).into_diagnostic()?.into()
            };

            let validity = Validity {
                not_before,
                not_after,
            };

            let signature_algorithm =
                issuer_kp.signature_algorithm(cert_config.digest_algorithm.as_ref())?;

            let spki_der = subject_kp.to_spki()?;
            let spki = SubjectPublicKeyInfo::from_der(spki_der.as_bytes()).into_diagnostic()?;

            let serial_number = hex::decode(&cert_config.serial_number)
                .into_diagnostic()
                .wrap_err(format!(
                    "Serial number of certificate \"{}\"",
                    cert_config.name
                ))?;
            if serial_number.len() > 20 {
                return Err(miette::miette!(
                    "Certificate serial number must be at most 20 octets"
                ));
            }

            let mut tbs_cert = TbsCertificate {
                version: x509_cert::Version::V3,
                serial_number: x509_cert::serial_number::SerialNumber::new(&serial_number)
                    .into_diagnostic()?,
                signature: signature_algorithm.clone(),
                issuer: issuer_dn,
                validity,
                subject: subject_entity.distinguished_name().clone(),
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            };

            if let Some(v) = &cert_config.extensions {
                for extension_config in v {
                    let extension = <dyn Extension>::from_config(
                        extension_config,
                        &tbs_cert,
                        issuer_cert.as_ref(),
                    )?;

                    let cert_extension = x509_cert::ext::Extension {
                        extn_id: extension.oid(),
                        critical: extension.is_critical(),
                        extn_value: x509_cert::der::asn1::OctetString::new(extension.as_der())
                            .into_diagnostic()?,
                    };

                    let mut ext_vec = if let Some(x) = tbs_cert.extensions {
                        x.clone()
                    } else {
                        Vec::new()
                    };
                    ext_vec.push(cert_extension);
                    tbs_cert.extensions = Some(ext_vec);
                }
            }

            let tbs_cert_der = tbs_cert.to_der().into_diagnostic()?;

            let cert_signature = issuer_kp
                .signature(cert_config.digest_algorithm.as_ref(), &tbs_cert_der)
                .wrap_err("signing cert")?;
            let cert = Certificate {
                tbs_certificate: tbs_cert,
                signature_algorithm: signature_algorithm.clone(),
                signature: BitString::from_bytes(&cert_signature).into_diagnostic()?,
            };

            let cert_filename = format!("{}.cert.pem", cert_config.name);
            let path = dir.join(&cert_filename);
            println!("Writing certificate to \"{}\"", &path);
            write_to_file(
                &path,
                cert.to_pem(LineEnding::CRLF).into_diagnostic()?.as_bytes(),
                opts,
            )?
        }

        Ok(())
    }

    fn load_keypairs(&self, dir: Utf8PathBuf) -> Result<HashMap<String, Box<dyn KeyPair>>> {
        let mut key_pairs = HashMap::new();

        for kp_config in &self.key_pairs {
            let kp_filename = format!("{}.key.pem", kp_config.name);
            let path = dir.join(&kp_filename);
            let kp_pem = std::fs::read_to_string(&path)
                .into_diagnostic()
                .wrap_err(format!(
                    "Unable to load key pair \"{}\" from \"{}\"",
                    kp_config.name, &path
                ))?;
            let kp = <dyn KeyPair>::from_pem(kp_config, &kp_pem)?;
            key_pairs.insert(String::from(kp.name()), kp);
        }

        Ok(key_pairs)
    }

    fn load_certificates(
        &self,
        dir: Utf8PathBuf,
    ) -> Result<HashMap<String, x509_cert::Certificate>> {
        let mut certs = HashMap::new();

        for cert_cfg in &self.certificates {
            let cert_filename = format!("{}.cert.pem", cert_cfg.name);
            let path = dir.join(&cert_filename);
            let cert_pem = std::fs::read_to_string(&path)
                .into_diagnostic()
                .wrap_err(format!(
                    "Unable to load certificate \"{}\" from \"{}\"",
                    cert_cfg.name, &path
                ))?;
            let cert = x509_cert::Certificate::from_pem(cert_pem).into_diagnostic()?;
            certs.insert(cert_cfg.name.clone(), cert);
        }

        Ok(certs)
    }

    fn load_entities(&self) -> Result<HashMap<String, Entity>> {
        let mut entity_map = HashMap::new();

        for entity_config in &self.entities {
            let entity = Entity::try_from(entity_config)?;
            entity_map.insert(String::from(entity.name()), entity);
        }

        Ok(entity_map)
    }

    pub fn validate(doc: config::Document) -> Result<ValidDocument> {
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

        let config::Document {
            key_pairs,
            entities,
            certificates,
            certificate_requests,
            certificate_lists,
        } = doc;

        Ok(ValidDocument {
            key_pairs,
            entities,
            certificates,
            certificate_requests,
            certificate_lists,
        })
    }
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub enum OutputFileExistsBehavior {
    Skip,
    Error,
    Overwrite,
}

pub fn write_to_file(
    path: &Utf8PathBuf,
    contents: &[u8],
    exists_behavior: OutputFileExistsBehavior,
) -> Result<()> {
    let mut open_opts = OpenOptions::new();
    open_opts.write(true);
    match exists_behavior {
        OutputFileExistsBehavior::Skip | OutputFileExistsBehavior::Error => {
            open_opts.create_new(true)
        }
        OutputFileExistsBehavior::Overwrite => open_opts.create(true).truncate(true),
    };

    let mut file = match open_opts.open(path) {
        Err(e)
            if e.kind() == std::io::ErrorKind::AlreadyExists
                && exists_behavior == OutputFileExistsBehavior::Skip =>
        {
            println!("File \"{}\" already exists, skipping", path);
            return Ok(());
        }
        x => x
            .into_diagnostic()
            .wrap_err(format!("Unable to open file \"{}\" for writing", path))?,
    };
    file.write_all(contents)
        .into_diagnostic()
        .wrap_err(format!("Unable to write to file \"{}\"", path))
}
