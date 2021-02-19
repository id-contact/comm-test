use std::{convert::TryFrom, error::Error as StdError, fmt::Display};
use serde::Deserialize;
use id_contact_jwe::{SignKeyConfig, EncryptionKeyConfig};

use josekit::{
    jwe::{JweDecrypter},
    jws::{JwsVerifier},
};

#[derive(Debug)]
pub enum Error {
    YamlError(serde_yaml::Error),
    Json(serde_json::Error),
    JWT(id_contact_jwe::Error),
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

impl From<id_contact_jwe::Error> for Error {
    fn from(e: id_contact_jwe::Error) -> Error {
        Error::JWT(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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

// This tryfrom can be removed once try_from for fields lands in serde
impl TryFrom<RawConfig> for Config {
    type Error = Error;
    fn try_from(config: RawConfig) -> Result<Config, Error> {
        Ok(Config {
            server_url: config.server_url,
            internal_url: config.internal_url,
            use_attr_url: config.use_attr_url,
            decrypter: Box::<dyn JweDecrypter>::try_from(config.decryption_privkey)?,
            validator: Box::<dyn JwsVerifier>::try_from(config.signature_pubkey)?,
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
