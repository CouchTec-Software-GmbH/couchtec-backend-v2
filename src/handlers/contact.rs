use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, Json};
use reqwest::StatusCode;
use serde_json::json;

use crate::{schema::ContactSchema, utils::internal_server_error, AppState};

pub async fn contact(
    State(data): State<Arc<AppState>>,
    Json(body): Json<ContactSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("contact");
    let _ = data
        .email_manager
        .send_contact_email(&body.name, &body.email, &body.message)
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
