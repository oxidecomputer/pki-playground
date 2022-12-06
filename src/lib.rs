use miette::{IntoDiagnostic, Result};
use pkcs8::{EncodePrivateKey, DecodePrivateKey};
use rsa::{RsaPrivateKey, PublicKeyParts, BigUint};
use zeroize::Zeroizing;

pub mod config;

pub trait KeyPair {
    fn name(&self) -> &str;

    fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>>;
}

impl dyn KeyPair {
    pub fn new(config: &config::KeyPair) -> Result<Box<dyn KeyPair>> {
        match &config.key_type[0] {
            config::KeyType::Rsa(x) => RsaKeyPair::new(&config.name, &x),
        }
    }

    pub fn from_pem(config: &config::KeyPair, s: &str) -> Result<Box<dyn KeyPair>> {
        match &config.key_type[0] {
            config::KeyType::Rsa(x) => RsaKeyPair::from_pem(&config.name, &x, s),
        }
    }
}

pub struct RsaKeyPair {
    name: String,
    private_key: Zeroizing<rsa::RsaPrivateKey>,
}

impl RsaKeyPair {
    pub fn new(name: &str, config: &config::RsaKeyConfig) -> Result<Box<dyn KeyPair>> {
        let mut rng = rand::thread_rng();

        Ok(Box::new(RsaKeyPair {
            name: name.into(),
            private_key: rsa::algorithms::generate_multi_prime_key_with_exp(
                &mut rng,
                config.num_primes,
                config.num_bits,
                &config.public_exponent.into(),
            )
            .into_diagnostic()?
            .into(),
        }))
    }

    pub fn from_pem(name: &str, config:&config::RsaKeyConfig, s: &str) -> Result<Box<dyn KeyPair>> {
        let private_key = Zeroizing::new(RsaPrivateKey::from_pkcs8_pem(s).into_diagnostic()?);
        if private_key.size()*8 != config.num_bits {
            miette::bail!("PEM-encoded RSA private key has modulus size {} but config specifies {}", private_key.size(), config.num_bits)
        }

        if private_key.e() != &BigUint::from(config.public_exponent) {
            miette::bail!("PEM-encoded RSA private key has public exponent {} but config specifies {}", private_key.e(), config.public_exponent)
        }

        Ok(Box::new(Self{
            name: name.into(),
            private_key: private_key,
        }))
    }
}

impl KeyPair for RsaKeyPair {
    fn name(&self) -> &str {
        &self.name
    }

    fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        self.private_key.to_pkcs8_pem(pkcs8::LineEnding::CRLF).into_diagnostic()
    }
}
