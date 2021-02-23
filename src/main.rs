use std::{error::Error as StdError, fmt::Display, fs::File};

use id_contact_jwe::decrypt_and_verify_attributes;
use id_contact_proto::{AuthResult, StartCommRequest, StartCommResponse};
use rocket::{get, launch, post, request::Form, routes, State};
use rocket_contrib::json::Json;

mod config;

use config::Config;

#[derive(Debug)]
enum Error {
    Config(config::Error),
    Json(serde_json::Error),
    Utf(std::str::Utf8Error),
    JWT(id_contact_jwe::Error),
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let debug_error = rocket::response::Debug::from(self);
        debug_error.respond_to(request)
    }
}

impl From<config::Error> for Error {
    fn from(e: config::Error) -> Error {
        Error::Config(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Utf(e)
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
            Error::Config(e) => e.fmt(f),
            Error::Utf(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::JWT(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Config(e) => Some(e),
            Error::Utf(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::JWT(e) => Some(e),
        }
    }
}

#[get("/ui")]
fn ui() -> &'static str {
    "Communication plugin UI"
}

#[get("/ui?<session_result..>")]
fn ui_withparams(
    session_result: Form<AuthResult>,
    config: State<Config>,
) -> Result<&'static str, Error> {
    println!(
        "Received inline authentication results {:?}",
        &session_result
    );

    if let Some(attributes) = &session_result.attributes {
        let attributes =
            decrypt_and_verify_attributes(attributes, config.validator(), config.decrypter())?;
        println!("Decoded attributes: {:?}", attributes);
    }

    Ok(ui())
}

#[post("/auth_result", data = "<auth_result>")]
fn attr_url(auth_result: Json<AuthResult>, config: State<Config>) -> Result<(), Error> {
    println!("Received authentication result {:?}", &auth_result);
    if let Some(attributes) = &auth_result.attributes {
        let attributes =
            decrypt_and_verify_attributes(attributes, config.validator(), config.decrypter())?;
        println!("Decoded attributes: {:?}", attributes);
    }

    Ok(())
}

#[post("/start_communication", data = "<request>")]
fn start(
    request: Json<StartCommRequest>,
    config: State<Config>,
) -> Result<Json<StartCommResponse>, Error> {
    println!("Received communication request {:?}", request);
    if let Some(attributes) = &request.attributes {
        let attributes =
            decrypt_and_verify_attributes(attributes, config.validator(), config.decrypter())?;
        println!("Decoded attributes: {:?}", attributes);
    }

    if config.use_attr_url() && request.attributes == None {
        Ok(Json(StartCommResponse {
            client_url: format!("{}/ui", config.server_url()),
            attr_url: Some(format!("{}/auth_result", config.internal_url())),
        }))
    } else {
        Ok(Json(StartCommResponse {
            client_url: format!("{}/ui", config.server_url()),
            attr_url: None,
        }))
    }
}

#[launch]
fn rocket() -> rocket::Rocket {
    let configfile = File::open(std::env::var("CONFIG").expect("No configuration file specified"))
        .expect("Could not open configuration");
    rocket::ignite()
        .mount("/", routes![start, attr_url, ui, ui_withparams,])
        .manage(Config::from_reader(&configfile).expect("Could not read configuration"))
}
