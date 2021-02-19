use std::{collections::HashMap, convert::TryFrom, error::Error as StdError, fmt::Display};
use serde::Deserialize;

use josekit::{
    jwe::{JweDecrypter, ECDH_ES, RSA_OAEP},
    jws::{JwsVerifier, ES256, RS256},
};

#[derive(Debug)]
pub enum Error {
    UnknownAttribute(String),
    YamlError(serde_yaml::Error),
    Json(serde_json::Error),
    JWT(josekit::JoseError),
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Error {
        Error::YamlError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<josekit::JoseError> for Error {
    fn from(e: josekit::JoseError) -> Error {
        Error::JWT(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownAttribute(a) => f.write_fmt(format_args!("Unknown attribute {}", a)),
            Error::YamlError(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::JWT(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::YamlError(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::JWT(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
struct InnerKeyConfig {
    key: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum EncryptionKeyConfig {
    RSA(InnerKeyConfig),
    EC(InnerKeyConfig),
}

impl EncryptionKeyConfig {
    fn to_decrypter(&self) -> Result<Box<dyn JweDecrypter>, Error> {
        match self {
            EncryptionKeyConfig::RSA(key) => Ok(Box::new(RSA_OAEP.decrypter_from_pem(&key.key)?)),
            EncryptionKeyConfig::EC(key) => Ok(Box::new(ECDH_ES.decrypter_from_pem(&key.key)?)),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum SignKeyConfig {
    RSA(InnerKeyConfig),
    EC(InnerKeyConfig),
}

impl SignKeyConfig {
    fn to_verifier(&self) -> Result<Box<dyn JwsVerifier>, Error> {
        match self {
            SignKeyConfig::RSA(key) => Ok(Box::new(RS256.verifier_from_pem(&key.key)?)),
            SignKeyConfig::EC(key) => Ok(Box::new(ES256.verifier_from_pem(&key.key)?)),
        }
    }
}

#[derive(Deserialize, Debug)]
struct RawConfig {
    server_url: String,
    internal_url: String,
    use_attr_url: bool,
    decryption_privkey: EncryptionKeyConfig,
    signature_pubkey: SignKeyConfig,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    server_url: String,
    internal_url: String,
    use_attr_url: bool,
    decrypter: Box<dyn JweDecrypter>,
    validator: Box<dyn JwsVerifier>,
}

impl TryFrom<RawConfig> for Config {
    type Error = Error;
    fn try_from(config: RawConfig) -> Result<Config, Error> {
        Ok(Config {
            server_url: config.server_url,
            internal_url: config.internal_url,
            use_attr_url: config.use_attr_url,
            decrypter: config.decryption_privkey.to_decrypter()?,
            validator: config.signature_pubkey.to_verifier()?,
        })
    }
}

impl Config {
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn internal_url(&self) -> &str {
        &self.internal_url
    }

    pub fn decrypter(&self) -> &dyn JweDecrypter {
        self.decrypter.as_ref()
    }

    pub fn validator(&self) -> &dyn JwsVerifier {
        self.validator.as_ref()
    }

    pub fn use_attr_url(&self) -> bool {
        self.use_attr_url
    }

    pub fn from_string(config: &str) -> Result<Config, Error> {
        Ok(serde_yaml::from_str(config)?)
    }

    pub fn from_reader<T: std::io::Read>(reader: T) -> Result<Config, Error> {
        Ok(serde_yaml::from_reader(reader)?)
    }
}
