use clap::Parser;
use miette::{Context, IntoDiagnostic, Result};
use pki_playground::KeyPair;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

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
        },
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
            }
        }
    }

    Ok(())
}
