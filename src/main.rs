use clap::Parser;
use const_oid::AssociatedOid;
use miette::{Context, IntoDiagnostic, Result};
use pkcs1::der::asn1::BitStringRef;
use pkcs1::der::{Decode, Encode};
use pkcs1::UIntRef;
use pkcs8::der::asn1::GeneralizedTime;
use pkcs8::der::DateTime;
use pkcs8::SubjectPublicKeyInfo;
use pki_playground::config::BasicConstraintsExtension;
use pki_playground::KeyPair;
use rsa::BigUint;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::ext::Extension;
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate};

#[derive(clap::Parser)]
struct Options {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand)]
enum Action {
    GenerateKeyPairs,
    GenerateCertificates,
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

    println!("{:#?}", doc);

    match opts.action {
        Action::GenerateKeyPairs => {
            for kp_config in &doc.key_pairs {
                let kp_filename = format!("{}.key.pem", kp_config.name);
                let mut kp_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&kp_filename)
                    .into_diagnostic()
                    .wrap_err(format!("Writing key pair to \"{}\"", &kp_filename))?;

                let kp = <dyn KeyPair>::new(kp_config)?;
                kp_file
                    .write_all(kp.to_pkcs8_pem()?.as_bytes())
                    .into_diagnostic()?;
            }
        }
        Action::GenerateCertificates => {
            let mut key_pairs = HashMap::new();
            for kp_config in &doc.key_pairs {
                let kp_filename = format!("{}.key.pem", kp_config.name);
                let kp_pem = std::fs::read_to_string(kp_filename).into_diagnostic()?;
                let kp = <dyn KeyPair>::from_pem(kp_config, &kp_pem)?;
                key_pairs.insert(String::from(kp.name()), kp);
            }

            let mut entities = HashMap::new();
            for entity_config in &doc.entities {
                let entity = pki_playground::Entity::try_from(entity_config)?;
                entities.insert(String::from(entity.name()), entity);
            }

            for cert_config in &doc.certificates {
                let subject_entity = entities.get(&cert_config.subject_entity).unwrap();
                let subject_kp = key_pairs.get(&cert_config.subject_key).unwrap();

                let issuer_entity = entities.get(&cert_config.issuer_entity).unwrap();
                let issuer_kp = key_pairs.get(&cert_config.issuer_key).unwrap();

                let not_after = GeneralizedTime::from(
                    DateTime::from_str(&cert_config.not_after).into_diagnostic()?,
                );
                let not_before = GeneralizedTime::from(match &cert_config.not_before {
                    None => DateTime::from_system_time(SystemTime::now()).into_diagnostic()?,
                    Some(x) => DateTime::from_str(x).into_diagnostic()?,
                });
                let validity = Validity {
                    not_before: not_before.into(),
                    not_after: not_after.into(),
                };

                let signature_algorithm =
                    issuer_kp.signature_algorithm(&cert_config.digest_algorithm);

                let spki_der = subject_kp.to_spki()?;
                let spki = SubjectPublicKeyInfo::from_der(spki_der.as_bytes()).into_diagnostic()?;

                let serial_number = BigUint::from(cert_config.serial_number).to_bytes_be();

                // TODO: Generate extensions from config.  Need an intermediate
                // object to store DER-encoded form of extension payload as
                // x509_cert::ext::Extension only takes a reference to the
                // payload.
                let mut extensions = Vec::new();

                let basic_ca_ext = BasicConstraints {
                    ca: true,
                    path_len_constraint: None,
                };
                let basic_ca_ext_der = basic_ca_ext.to_vec().into_diagnostic()?;

                extensions.push(Extension {
                    extn_id: BasicConstraints::OID,
                    critical: true,
                    extn_value: &basic_ca_ext_der,
                });

                let tbs_cert = TbsCertificate {
                    version: x509_cert::Version::V3,
                    serial_number: UIntRef::new(&serial_number).into_diagnostic()?,
                    signature: signature_algorithm,
                    issuer: issuer_entity.distinguished_name().clone(),
                    validity: validity,
                    subject: subject_entity.distinguished_name().clone(),
                    subject_public_key_info: spki,
                    issuer_unique_id: None,
                    subject_unique_id: None,
                    extensions: Some(extensions),
                };
                let tbs_cert_der = tbs_cert.to_vec().into_diagnostic()?;

                let cert_signature = issuer_kp
                    .signature(&cert_config.digest_algorithm, &tbs_cert_der)
                    .wrap_err("signing cert")?;
                let cert = Certificate {
                    tbs_certificate: tbs_cert,
                    signature_algorithm: signature_algorithm,
                    signature: BitStringRef::from_bytes(&cert_signature).into_diagnostic()?,
                };

                let cert_filename = format!("{}.cert.der", cert_config.name);
                let mut cert_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&cert_filename)
                    .into_diagnostic()
                    .wrap_err(format!("Writing cert to \"{}\"", &cert_filename))?;

                cert_file
                    .write_all(&cert.to_vec().into_diagnostic()?)
                    .into_diagnostic()?;
            }
        }
    }

    Ok(())
}
