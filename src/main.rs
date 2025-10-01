// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use camino::Utf8PathBuf;
use clap::Parser;
use miette::{Context, Result};
use pki_playground::OutputFileExistsBehavior;

#[derive(clap::Parser)]
struct Options {
    #[arg(short, long, value_name = "FILE")]
    config: Option<Utf8PathBuf>,

    #[command(subcommand)]
    action: Action,
}

#[allow(clippy::enum_variant_names)]
#[derive(clap::Subcommand)]
enum Action {
    GenerateKeyPairs(GenerateKeyPairsOpts),
    GenerateCertificateRequests(GenerateCertificateRequestsOpts),
    GenerateCertificates(GenerateCertificatesOpts),
    GenerateCertificateLists(GenerateCertificateListsOpts),
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

#[derive(clap::Args)]
struct GenerateCertificateListsOpts {
    /// action to take if an output file already exists
    #[arg(long, default_value = "overwrite")]
    output_exists: OutputFileExistsBehavior,
}

fn main() -> Result<()> {
    let opts = Options::parse();

    let config_path = match opts.config {
        Some(x) => x,
        None => "config.kdl".into(),
    };

    let doc = pki_playground::config::load_and_validate(&config_path)
        .wrap_err(format!("Loading config from \"{}\" failed", config_path))?;

    let dir = ".".into();

    match opts.action {
        Action::GenerateCertificateLists(action_opts) => {
            doc.write_certificate_lists(dir, action_opts.output_exists)
        }
        Action::GenerateKeyPairs(action_opts) => {
            doc.write_key_pairs(dir, action_opts.output_exists)
        }
        Action::GenerateCertificateRequests(action_opts) => {
            doc.write_certificate_requests(dir, action_opts.output_exists)
        }
        Action::GenerateCertificates(action_opts) => {
            doc.write_certificates(dir, action_opts.output_exists)
        }
    }
}
