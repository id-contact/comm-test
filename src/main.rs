use std::{error::Error as StdError, fmt::Display};

use id_contact_jwt::decrypt_and_verify_auth_result;
use id_contact_proto::{StartCommRequest, StartCommResponse};
use rocket::{get, launch, post, routes, serde::json::Json, State};

mod config;

use config::Config;

#[derive(Debug)]
enum Error {
    Config(config::Error),
    Json(serde_json::Error),
    Utf(std::str::Utf8Error),
    Jwt(id_contact_jwt::Error),
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

impl From<id_contact_jwt::Error> for Error {
    fn from(e: id_contact_jwt::Error) -> Error {
        Error::Jwt(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(e) => e.fmt(f),
            Error::Utf(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::Jwt(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Config(e) => Some(e),
            Error::Utf(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::Jwt(e) => Some(e),
        }
    }
}

#[get("/ui")]
fn ui() -> &'static str {
    "Communication plugin UI"
}

#[get("/ui?<result>")]
fn ui_withparams(result: String, config: &State<Config>) -> Result<&'static str, Error> {
    println!("Received inline authentication results {:?}", &result);

    let session_result =
        decrypt_and_verify_auth_result(&result, config.verifier(), config.decrypter())?;
    println!("Decoded: {:?}", session_result);

    Ok(ui())
}

#[post("/auth_result", data = "<auth_result>")]
fn attr_url(auth_result: String, config: &State<Config>) -> Result<(), Error> {
    println!("Received authentication result {:?}", &auth_result);
    let auth_result =
        decrypt_and_verify_auth_result(&auth_result, config.verifier(), config.decrypter())?;
    println!("Decoded: {:?}", auth_result);

    Ok(())
}

#[post("/start_communication", data = "<request>")]
fn start(
    request: Json<StartCommRequest>,
    config: &State<Config>,
) -> Result<Json<StartCommResponse>, Error> {
    println!("Received communication request {:?}", request);
    if let Some(auth_result) = &request.auth_result {
        let auth_result =
            decrypt_and_verify_auth_result(auth_result, config.verifier(), config.decrypter())?;
        println!("Decoded auth_result: {:?}", auth_result);
    }

    if config.use_attr_url() && request.auth_result == None {
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
fn rocket() -> _ {
    let base = rocket::build().mount("/", routes![start, attr_url, ui, ui_withparams,]);
    let config = base.figment().extract::<Config>().unwrap_or_else(|_| {
        // Drop error value, as it could contain secrets
        panic!("Failure to parse configuration")
    });

    base.manage(config)
}
