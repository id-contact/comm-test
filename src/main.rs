use std::{fmt::Display, fs::File, error::Error as StdError};

use rocket::{get, post, launch, routes, State};
use rocket_contrib::json::Json;

mod jwe;
mod config;
mod idcomm;

use idcomm::{AuthResult, CommRequest, CommResponse};
use config::Config;

#[derive(Debug)]
enum Error {
    Config(config::Error),
    Json(serde_json::Error),
    Utf(std::str::Utf8Error),
    JWT(jwe::Error),
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

impl From<jwe::Error> for Error {
    fn from(e: jwe::Error) -> Error {
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

#[get("/ui?<status>&<attributes>&<session_url>")]
fn ui_withparams(status: String, attributes: Option<String>, session_url: Option<String>, config: State<Config>) -> Result<&'static str, Error> {
    println!("Received inline authentication results");
    println!("status: {:?}", status);
    println!("attributes: {:?}", attributes);
    println!("session_url: {:?}", session_url);

    if let Some(attributes) = &attributes {
        let attributes = jwe::decrypt_and_verify_attributes(attributes, config.validator(), config.decrypter())?;
        println!("Decoded attributes: {:?}", attributes);
    }
    
    Ok(ui())
}

#[post("/auth_result", data = "<auth_result>")]
fn attr_url(auth_result: Json<AuthResult>, config: State<Config>) -> Result<(), Error> {
    println!("Received authentication result {:?}", &auth_result);
    if let Some(attributes) = &auth_result.attributes {
        let attributes = jwe::decrypt_and_verify_attributes(attributes, config.validator(), config.decrypter())?;
        println!("Decoded attributes: {:?}", attributes);
    }

    Ok(())
}

#[post("/start_communication", data = "<request>")]
fn start(request: Json<CommRequest>, config: State<Config>) -> Result<Json<CommResponse>, Error> {
    println!("Received communication request {:?}", request);
    if let Some(attributes) = &request.attributes {
        let attributes = jwe::decrypt_and_verify_attributes(attributes, config.validator(), config.decrypter())?;
        println!("Decoded attributes: {:?}", attributes);
    }

    if config.use_attr_url() && request.attributes == None {
        Ok(Json(CommResponse{ client_url: format!("{}/ui", config.server_url()), attr_url: Some(format!("{}/auth_result", config.internal_url()))}))
    } else {
        Ok(Json(CommResponse{ client_url: format!("{}/ui", config.server_url()), attr_url: None}))
    }
}

#[launch]
fn rocket() -> rocket::Rocket {
    let configfile = File::open(std::env::var("CONFIG").expect("No configuration file specified"))
        .expect("Could not open configuration");
    rocket::ignite()
        .mount(
            "/",
            routes![
                start,
                attr_url,
                ui,
                ui_withparams,
            ],
        )
        .manage(Config::from_reader(&configfile).expect("Could not read configuration"))
}
