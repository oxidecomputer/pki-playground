// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::{Parser, ValueEnum};
use miette::{miette, Context, IntoDiagnostic, Result};
use pem_rfc7468::LineEnding;
use pki_playground::{config, Entity, Extension, KeyPair};
use spki::SubjectPublicKeyInfo;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
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

#[derive(clap::Parser)]
struct Options {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    action: Action,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum OutputFileExistsBehavior {
    Skip,
    Error,
    Overwrite,
}

#[allow(clippy::enum_variant_names)]
#[derive(clap::Subcommand)]
enum Action {
    GenerateKeyPairs(GenerateKeyPairsOpts),
    GenerateCertificateRequests(GenerateCertificateRequestsOpts),
    GenerateCertificates(GenerateCertificatesOpts),
}

#[derive(clap::Args)]
struct GenerateKeyPairsOpts {
    /// action to take if an output file already exists
    #[arg(long, default_value = "skip")]
    output_exists: OutputFileExistsBehavior,
}

#[derive(clap::Args)]
struct GenerateCertificateRequestsOpts {
    /// action to take if an output file already exists
    #[arg(long, default_value = "overwrite")]
    output_exists: OutputFileExistsBehavior,
}

#[derive(clap::Args)]
struct GenerateCertificatesOpts {
    /// action to take if an output file already exists
    #[arg(long, default_value = "overwrite")]
    output_exists: OutputFileExistsBehavior,
}

fn write_to_file(
    filename: &str,
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

    let mut file = match open_opts.open(filename) {
        Err(e)
            if e.kind() == std::io::ErrorKind::AlreadyExists
                && exists_behavior == OutputFileExistsBehavior::Skip =>
        {
            println!("File \"{}\" already exists, skipping", filename);
            return Ok(());
        }
        x => x
            .into_diagnostic()
            .wrap_err(format!("Unable to open file \"{}\" for writing", filename))?,
    };
    file.write_all(contents)
        .into_diagnostic()
        .wrap_err(format!("Unable to write to file \"{}\"", filename))
}

fn load_keypairs(
    key_pairs_cfg: &Vec<config::KeyPair>,
) -> Result<HashMap<String, Box<dyn KeyPair>>> {
    let mut key_pairs = HashMap::new();

    for kp_config in key_pairs_cfg {
        let kp_filename = format!("{}.key.pem", kp_config.name);
        let kp_pem = std::fs::read_to_string(&kp_filename)
            .into_diagnostic()
            .wrap_err(format!(
                "Unable to load key pair \"{}\" from \"{}\"",
                kp_config.name, &kp_filename
            ))?;
        let kp = <dyn KeyPair>::from_pem(kp_config, &kp_pem)?;
        key_pairs.insert(String::from(kp.name()), kp);
    }

    Ok(key_pairs)
}

fn load_entities(entities: &Vec<config::Entity>) -> Result<HashMap<String, Entity>> {
    let mut entity_map = HashMap::new();

    for entity_config in entities {
        let entity = pki_playground::Entity::try_from(entity_config)?;
        entity_map.insert(String::from(entity.name()), entity);
    }

    Ok(entity_map)
}

fn main() -> Result<()> {
    let opts = Options::parse();

    let config_path = match opts.config {
        Some(x) => x,
        None => "config.kdl".into(),
    };

    let doc = pki_playground::config::load_and_validate(&config_path).wrap_err(format!(
        "Loading config from \"{}\" failed",
        config_path.display()
    ))?;

    match opts.action {
        Action::GenerateKeyPairs(action_opts) => {
            for kp_config in &doc.key_pairs {
                let kp = <dyn KeyPair>::new(kp_config)?;
                let kp_filename = format!("{}.key.pem", kp_config.name);
                println!("Writing key pair to \"{}\"", &kp_filename);
                write_to_file(
                    &kp_filename,
                    kp.to_pkcs8_pem()?.as_bytes(),
                    action_opts.output_exists,
                )?
            }
        }
        Action::GenerateCertificateRequests(action_opts) => {
            let key_pairs = load_keypairs(&doc.key_pairs)?;
            let entities = load_entities(&doc.entities)?;

            for csr_config in &doc.certificate_requests {
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
                println!("Writing certificate request to \"{}\"", &csr_filename);
                write_to_file(
                    &csr_filename,
                    csr.to_pem(LineEnding::CRLF).into_diagnostic()?.as_bytes(),
                    action_opts.output_exists,
                )?
            }
        }
        Action::GenerateCertificates(action_opts) => {
            let key_pairs = load_keypairs(&doc.key_pairs)?;
            let entities = load_entities(&doc.entities)?;

            for cert_config in &doc.certificates {
                let subject_entity = entities.get(&cert_config.subject_entity).ok_or(miette!(
                    "Subject entity for certificate {} does not exist: {}",
                    &cert_config.name,
                    &cert_config.subject_entity,
                ))?;
                let subject_kp = key_pairs.get(&cert_config.subject_key).unwrap();

                let issuer_cert_pem =
                    if let Some(issuer_cert_name) = &cert_config.issuer_certificate {
                        let issuer_cert_filename = format!("{}.cert.pem", issuer_cert_name);
                        let mut issuer_cert_pem = Vec::new();
                        let mut issuer_cert_file = std::fs::File::open(&issuer_cert_filename)
                            .into_diagnostic()
                            .wrap_err(format!(
                                "Unable to load issuer certificate \"{}\" from file \"{}\"",
                                issuer_cert_name, issuer_cert_filename
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

                let issuer_kp = key_pairs.get(&cert_config.issuer_key).unwrap();

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
                println!("Writing certificate to \"{}\"", &cert_filename);
                write_to_file(
                    &cert_filename,
                    cert.to_pem(LineEnding::CRLF).into_diagnostic()?.as_bytes(),
                    action_opts.output_exists,
                )?
            }
        }
    }

    Ok(())
}
