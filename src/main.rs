use clap::Parser;
use miette::{Context, IntoDiagnostic, Result};
use pki_playground::KeyPair;
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
    }

    Ok(())
}
