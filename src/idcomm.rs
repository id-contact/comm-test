use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthStatus {
    #[serde(rename = "succes")]
    Succes(),
    #[serde(rename = "failed")]
    Failed(),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResult {
    pub status: AuthStatus,
    pub attributes: Option<String>,
    pub session_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommRequest {
    pub purpose: String,
    pub attributes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommResponse {
    pub client_url: String,
    pub attr_url: Option<String>,
}
