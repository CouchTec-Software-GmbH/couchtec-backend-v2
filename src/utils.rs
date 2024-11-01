use std::{hash, sync::Arc};

use axum::{extract::State, http::StatusCode, Json};
use reqwest::Response;
use serde_json::{json, Value};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{schema::SessionVerifySchema, AppState};

pub async fn verify_session_token(
    State(data): State<Arc<AppState>>,
    Json(body): Json<SessionVerifySchema>,
) -> bool {
    true
}

pub fn get_new_code() -> (String, String, String) {
    let code = Uuid::new_v4().to_string();
    let (hashed, salt) = hash_code(&code);
    (hashed, salt, code)
}

pub fn hash_code(code: &str) -> (String, String) {
    let salt = Uuid::new_v4().to_string();
    (hash_code_salt(code, &salt), salt)
}

pub fn hash_code_salt(code: &str, salt: &str) -> String {
    let salted = format!("{}{}", code, salt);
    let mut hasher = Sha256::new();
    hasher.update(salted.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn internal_server_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "status": "error",
            "message": "Internal Server Error"
        })),
    )
}

pub async fn unpack_response_body(
    response: Response,
) -> Result<Value, (StatusCode, Json<serde_json::Value>)> {
    let response_body = response.json::<serde_json::Value>().await.map_err(|e| {
        println!("register fail: get response body: {:?}", e);
        internal_server_error()
    })?;

    let rows = response_body["rows"].as_array().ok_or(()).map_err(|e| {
        println!("error while converting reponse body to array");
        internal_server_error()
    })?;

    if rows.is_empty() {
        let error_response = json!({
            "status": "fail",
            "message": "Response body is empty."
        });
        return Err((StatusCode::NOT_FOUND, Json(error_response)));
    }
    Ok(rows[0]["value"].clone())
}

pub async fn update_doc(
    doc: &Value,
    data: Arc<AppState>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let viewer_id = doc["_id"].as_str().unwrap_or_default();
    let revision = doc["_rev"].as_str().unwrap_or_default();
    let update_url = format!("{}/viewers/{}", data.couchdb_url, viewer_id);
    let update_response = data
        .db_client
        .put(&update_url)
        .header("If-Match", revision)
        .json(&doc)
        .send()
        .await
        .map_err(|e| {
            println!("pre_register fail: update viewer document failed: {:?}", e);
            internal_server_error()
        })?;

    if !update_response.status().is_success() {
        let error_response = json!({
            "status": "error",
            "message": "Internal Server Error: Failed to update viewer document"
        });
        println!("utils fail: update viewer document failed");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
    }
    Ok(())
}

pub async fn get_viewer_response_by_email(
    data: Arc<AppState>,
    email: &str,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let url = format!(
        "{}/viewers/_design/viewer_views/_view/by_email?key=\"{}\"",
        data.couchdb_url, email
    );
    let response = data.db_client.get(&url).send().await.map_err(|e| {
        println!("register: failed to fetch pre-registration: {:?}", e);
        internal_server_error()
    })?;

    if !response.status().is_success() {
        let error_response = json!({
            "status": "fail",
            "message": "Verification failed: No matching viewer found."
        });
        println!("register: fail: No matching record found.");
        return Err((StatusCode::NOT_FOUND, Json(error_response)));
    }
    Ok(response)
}
