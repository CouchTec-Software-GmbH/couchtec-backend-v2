mod email;
mod handlers;
mod route;
mod schema;
mod utils;

use axum::extract::DefaultBodyLimit;
use dotenv::dotenv;
use email::EmailManager;
use reqwest::Client;
use std::{env, process::exit, sync::Arc};

pub struct AppState {
    db_client: Arc<Client>,
    couchdb_url: String,
    email_manager: Arc<EmailManager>,
    url: String,
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let couchdb_url = env::var("COUCHDB_URL").expect("COUCHDB_URL must be set!");
    let couchdb_username = env::var("COUCHDB_USERNAME").expect("COUCHDB_USERNAME must be set!");
    let couchdb_password = env::var("COUCHDB_PASSWORD").expect("COUCHDB_PASSWORD must be set!");
    let url = env::var("URL").expect("URL must be set!");

    let smtp_email = env::var("SMTP_EMAIL").expect("SMTP_EMAIL must be set");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
    let email_manager = match EmailManager::new(&smtp_email, &smtp_password) {
        Ok(manager) => Arc::new(manager),
        Err(e) => {
            eprintln!("Failed to create EmailManager: {:?}", e);
            std::process::exit(1);
        }
    };

    let db_client = Arc::new(Client::new());

    // Test CouchDB connection
    let encoded_password = urlencoding::encode(&couchdb_password).to_string();
    let couchdb_url = format!(
        "https://{}:{}@{}",
        couchdb_username, encoded_password, couchdb_url
    );

    let test_url = format!(
        "{}/_all_dbs",
        &couchdb_url
    );
    match db_client
        .get(&test_url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            println!("Connection to CouchDB successful");
        }
        Ok(response) => {
            // Print error response if not successful
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".into());
            eprintln!("Failed to connect to CouchDB: {}", error_text);
            exit(1);
        }
        Err(err) => {
            eprintln!("Failed to connect to CouchDB: {:?}", err);
            exit(1);
        }
    }

    let app = route::create_router(Arc::new(AppState {
        db_client,
        couchdb_url,
        email_manager: email_manager.clone(),
        url,
    }))
    .layer(DefaultBodyLimit::max(40 * 1024 * 1024));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
