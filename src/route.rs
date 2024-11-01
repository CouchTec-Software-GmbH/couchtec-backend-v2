use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

use crate::{
    handlers::{
        auth::{login, pre_register, pre_reset_password, register, reset_password},
    },
    AppState,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);
    Router::new()
        .route("/api/pre-register", post(pre_register))
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/pre-reset-password", post(pre_reset_password))
        .route("/api/reset-password", post(reset_password))
        .layer(cors)
        .with_state(app_state)
}
