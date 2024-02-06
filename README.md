# pki-playground

WARNING: `pki-playground` creates cryptographic keys that are intended **ONLY**
for internal use. These keys are not intended for and **MUST NOT** be used for
any other purpose.

This repo hosts software for generating [RFC
2986](https://datatracker.ietf.org/doc/html/rfc2986) CSRs and [RFC
5280](https://datatracker.ietf.org/doc/html/rfc5280) certs and cert hierarchies
from a [KDL](https://kdl.dev/) specification.

## Build & Run

We use [cargo](https://doc.rust-lang.org/cargo/) to build and run the
`pki-playground`. Run the `cargo build` command to compile it, then run the
`pki-playground` binary with `cargo run`. Get additional documentation for the
options and parameters accepted with the `--help` option: `cargo run -- --help`
