use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Path, State},
    http::{
        header::{self},
        request::Parts,
        HeaderMap, StatusCode,
    },
    response::IntoResponse,
    Json,
};
use axum_extra::{extract::CookieJar, TypedHeader};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower_http::classify::StatusInRangeAsFailures;
use uuid::Uuid;

use crate::{
    schema::{
        LoginSchema, PreRegisterSchema, PreResetPasswordSchema, RegisterSchema, ResetPasswordSchema,
    },
    utils::{self, get_new_code, get_viewer_response_by_email, hash_code, hash_code_salt, internal_server_error, unpack_response_body, update_doc},
    AppState,
};

pub async fn pre_register(
    State(data): State<Arc<AppState>>,
    Json(body): Json<PreRegisterSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("pre_register");

    let (hashed_password, salt) = utils::hash_code(&body.password);
    let verification_code = Uuid::new_v4().to_string();
    let (verification_code_hashed, verification_salt) = utils::hash_code(&verification_code);

    let verification_entry = json!({
        "verification_code_hashed": verification_code_hashed,
        "verification_salt": verification_salt,
        "was_used": false,
        "created_at": Utc::now().to_rfc3339(),
        "expires_at": (Utc::now() + Duration::hours(2)).to_rfc3339(),
    });

   let response = get_viewer_response_by_email(data.clone(), &body.email).await?;

    if response.status().is_success() {
        let viewer_data = response.json::<serde_json::Value>().await.unwrap();
        let rows = viewer_data["rows"].as_array().unwrap();
    
        if !rows.is_empty() {
            let mut viewer_doc = rows[0]["value"].clone();
            if viewer_doc["verification_codes"].is_null() || !viewer_doc["verification_codes"].is_array() {
                viewer_doc["verification_codes"] = json!([]);
            }
            let verification_codes = viewer_doc["verification_codes"].as_array_mut().ok_or_else(|| {
                internal_server_error()
            })?;
            verification_codes.push(verification_entry);
            update_doc(&viewer_doc, data.clone()).await?;
        } else {
            let viewer_doc = json!({
                "type": "viewer",
                "email": body.email,
                "newsletter": body.newsletter,
                "hashed_password": hashed_password,
                "salt": salt,
                "verified": false,
                "verification_codes": [verification_entry],
                "sessions": [],
                "reset_password_codes": [],
                "is_admin": false,
                "created_at": chrono::Utc::now().to_rfc3339(),
            });

            let response = data.db_client
                .post(format!("{}/viewers", data.couchdb_url))
                .json(&viewer_doc)
                .send()
                .await
                .map_err(|e| {
                    println!("pre_register fail: post viewer to couchdb failed: {:?}", e);
                    internal_server_error()
                })?;

            if !response.status().is_success() {
                let error_response = json!({
                    "status": "error",
                    "message": "Failed to create viewer document"
                });
                println!("pre_register fail: failed to create viewer");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)));
            }
        }
    }
  
    let _ = data
        .email_manager
        .send_verify_email(&body.email, &data.url, &verification_code, "")
        .map_err(|e| {
            println!("Something went wrong while trying to send verication E-Mail: {:?}", e);
            internal_server_error()
        })?;

    let response = json!({
        "status": "success",
        "data": "E-Mail sent."
    });
    Ok((StatusCode::OK, Json(response)))
}

pub async fn register(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RegisterSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("register");
    let response = get_viewer_response_by_email(data.clone(), &body.email).await?;
    let mut viewer_doc = unpack_response_body(response).await?;

let is_verified = viewer_doc["verified"].as_bool().ok_or_else(|| internal_server_error())?;
    if is_verified {
        let response = json!({
            "status": "success",
            "data": "Viewer registered."
        });
        return Ok((StatusCode::OK, Json(response)));
    }
    let verification_codes = viewer_doc["verification_codes"].as_array_mut().ok_or("").map_err(|e| {
        println!("No Verification Codes in user document: {:?}", e);
        internal_server_error()
    })?;

    let verification_entry = verification_codes.iter_mut().find(|code| {
        let was_used = code["was_used"].as_bool().unwrap_or(false);
        let is_expired = if let Some(value) = code["expires_at"].as_str() {
            match DateTime::parse_from_rfc3339(value) {
                Ok(v) => v < Utc::now(),
                Err(_) => true
            }
        } else {
            true
        };
        if was_used || is_expired {
            return false;
        }

        let verification_salt = code["verification_salt"].as_str().unwrap_or_default();
        let salted_code = format!("{}{}", body.verification_code, verification_salt);
        let mut hasher = Sha256::new();
        hasher.update(salted_code.as_bytes());
        let hashed_verification_code = hex::encode(hasher.finalize());

        hashed_verification_code == code["verification_code_hashed"].as_str().unwrap_or_default()
    });

    if let Some(entry) = verification_entry {
        entry["was_used"] = json!(true);
        viewer_doc["verified"] = json!(true);
        update_doc(&viewer_doc, data.clone()).await?;
    } else {
        let error_response = json!({
            "status": "fail",
            "message": "No valid verification code found."
        });
        println!("register: fail: Valid Verification code does not exist.");
        return Err((StatusCode::FORBIDDEN, Json(error_response)));
    }

    let response = json!({
        "status": "success",
        "data": "Viewer registered."
    });
    Ok((StatusCode::OK, Json(response)))
}

pub async fn login(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("login");
    let response = get_viewer_response_by_email(data.clone(), &body.email).await?;
    let mut viewer_doc = unpack_response_body(response).await?;
    if !viewer_doc["verified"].as_bool().unwrap_or(false) {
        let response = json!({
            "status": "fail",
            "data": "User not Verified."
        });
        return Err((StatusCode::FORBIDDEN, Json(response)));
    }

    let salt = &viewer_doc["salt"].as_str().unwrap_or_default();
    let hashed_password = hash_code_salt(&body.password, &salt);

    if hashed_password != viewer_doc["hashed_password"].as_str().unwrap_or_default() {
        let response = json!({
            "status": "fail",
            "data": "Password does not match."
        });
        return Err((StatusCode::FORBIDDEN, Json(response)));
    }

    let (session_token, salt, code) = get_new_code();

    let session_entry = json!({
        "session_code_hashed": session_token,
        "session_salt": salt,
        "created_at": Utc::now().to_rfc3339(),
        "expires_at": (Utc::now() + Duration::hours(2)).to_rfc3339(),
    });

    let sessions = viewer_doc["sessions"].as_array_mut().ok_or_else(|| {
        println!("No sessions field in viewer_doc");
        internal_server_error()
    })?;
    sessions.push(session_entry);
    update_doc(&viewer_doc, data.clone()).await?;


    // Set the session token as an HTTP-only cookie
    let session_token_cookie = format!(
        "session_token={}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age={}",
        session_token,
        60 * 60 * 24 * 7 // 1 week in seconds
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.append(header::SET_COOKIE, session_token_cookie.parse().unwrap());


    let response = json!({
        "status": "success",
        "data": "User logged in."
    });
    println!("Login successful.");
    Ok((StatusCode::OK, headers, Json(response)).into_response())
}

pub async fn pre_reset_password(
    State(data): State<Arc<AppState>>,
    Json(body): Json<PreResetPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("pre_reset_password");
    let response = get_viewer_response_by_email(data.clone(), &body.email).await?;
    let mut viewer_doc = unpack_response_body(response).await?;
    println!("Got Viewer doc");

    let is_verified = viewer_doc["verified"].as_bool().ok_or_else(|| internal_server_error())?;
    if !is_verified {
        let response = json!({
            "status": "fail",
            "data": "Viewer not verified."
        });
        return Err((StatusCode::FORBIDDEN, Json(response)));
    }
    let (reset_password_token, salt, code) =  get_new_code();
    let reset_password_entry = json!({
        "reset_password_hashed": reset_password_token,
        "salt": salt,
        "was_used": false,
        "created_at": Utc::now().to_rfc3339(),
        "expires_at": (Utc::now() + Duration::hours(2)).to_rfc3339(),
    });

    let reset_password_codes = viewer_doc["reset_password_codes"].as_array_mut().ok_or_else(|| {
        internal_server_error()
    })?;
    reset_password_codes.push(reset_password_entry);
    update_doc(&viewer_doc, data.clone()).await?;
    
    let _ = data
        .email_manager
        .send_reset_password_email(&body.email, &data.url, &code, &viewer_doc["first_name"].as_str().unwrap_or(""))
        .map_err(|e| {
            println!("Something went wrong while trying to send reset password E-Mail: {:?}", e);
            internal_server_error()
        })?;

    let response = json!({
        "status": "success",
        "message": "Zurücksetzungs E-Mail gesendet."
    });

    Ok((StatusCode::OK, Json(response)))
}

pub async fn reset_password(
    State(data): State<Arc<AppState>>,
    Json(body): Json<ResetPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("pre_reset_password");

    let response = get_viewer_response_by_email(data.clone(), &body.email).await?;
    let mut viewer_doc = unpack_response_body(response).await?;

    let is_verified = viewer_doc["verified"].as_bool().ok_or_else(|| internal_server_error())?;
    if !is_verified {
        let response = json!({
            "status": "fail",
            "data": "Viewer not verified."
        });
        return Err((StatusCode::FORBIDDEN, Json(response)));
    }

    let reset_password_codes = viewer_doc["reset_password_codes"].as_array_mut().ok_or_else(|| {
        internal_server_error()
    })?;

    let reset_password_entry = reset_password_codes.iter_mut().find(|code| {
        let was_used = code["was_used"].as_bool().unwrap_or(false);
        let is_expired = if let Some(value) = code["expires_at"].as_str() {
            match DateTime::parse_from_rfc3339(value) {
                Ok(v) => v < Utc::now(),
                Err(_) => true
            }
        } else {
            true
        };
        if was_used || is_expired {
            println!("Was used or is expired");
            return false;
        }
        let salt = code["salt"].as_str().unwrap_or_default();
        let hashed_verification_code = hash_code_salt(&body.reset_password_token, salt);

        println!("hashed: {}", hashed_verification_code);
        hashed_verification_code == code["reset_password_hashed"].as_str().unwrap_or_default()
    });

    
    if let Some(entry) = reset_password_entry {
        entry["was_used"] = json!(true);
        let (hashed, salt) = hash_code(&body.password);
        viewer_doc["hashed_password"] = json!(hashed);
        viewer_doc["salt"] = json!(salt);
        update_doc(&viewer_doc, data.clone()).await?;
    } else {
        let error_response = json!({
            "status": "fail",
            "message": "No valid reset password token found."
        });
        println!("register: fail: Valid reset password token does not exist.");
        return Err((StatusCode::FORBIDDEN, Json(error_response)));
    }

    let response = json!({
        "status": "success",
        "message": "Password reset."
    });

    Ok((StatusCode::OK, Json(response)))
}

pub struct AuthenticatedViewer {
    pub viewer_id: Uuid,
    pub is_admin: bool,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedViewer
where
    Arc<AppState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, data: &S) -> Result<Self, Self::Rejection> {
        let data = Arc::from_ref(data);

        let jar = CookieJar::from_request_parts(parts, &data)
            .await
            .map_err(|e| {
                println!("verify user fail: {:?}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!( {
                                "status": "fail",
                                "message": "Unauthorized - Missing cookies."
                    })),
                )
            })?;

        let session_token = jar.get("session_token");
        if session_token.is_none() {
            println!("verify user fail: no session token found in cookie");
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "fail",
                    "message": "Unauthorized - Missing session token."
                })),
            ));
        }
        let session_token = session_token.unwrap().value();

        let session_id = jar.get("session_id");
        if session_id.is_none() {
            println!("verify user fail: no session id found in cookie");
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "fail",
                    "message": "Unauthorized - Missing session id."
                })),
            ));
        }
        let session_id = session_id.unwrap().value();
        let session_id = match Uuid::parse_str(session_id) {
            Ok(id) => id,
            Err(_) => {
                println!("verify user fail: session_id in cookie not a uuid");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "status": "fail",
                        "message": "Invalid session ID."
                    })),
                ));
            }
        };

        let viewer_id = Uuid::new_v4();

        Ok(AuthenticatedViewer {
            viewer_id,
            is_admin: false,
        })
    }
}
