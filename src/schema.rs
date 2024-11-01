use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PreRegisterSchema {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterSchema {
    pub verification_code: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginSchema {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PreResetPasswordSchema {
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResetPasswordSchema {
    pub email: String,
    pub password: String,
    pub reset_password_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionVerifySchema {
    pub email: String,
    pub session_token: String,
}
