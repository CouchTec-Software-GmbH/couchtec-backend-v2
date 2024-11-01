use lettre::message::header::{self};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::{Error as SmtpError, SmtpTransport};
use lettre::{Address, Message, Transport};
use thiserror::Error;
pub struct EmailManager {
    email: String,
    smtp_transport: SmtpTransport,
}

#[derive(Error, Debug)]
pub enum EmailManagerError {
    #[error("SMTP error: {0}")]
    Smtp(#[from] SmtpError),
    #[error("Invalid email address: {0}")]
    InvalidEmail(#[from] lettre::address::AddressError),
    #[error("Faild to build email address: {0}")]
    BuildMessage(#[from] lettre::error::Error),
}

impl EmailManager {
    pub fn new(smtp_email: &str, smtp_password: &str) -> Result<Self, SmtpError> {
        let creds = Credentials::new(smtp_email.to_string(), smtp_password.to_string());
        let mailer = SmtpTransport::relay("smtp.gmail.com")?
            .credentials(creds)
            .build();
        Ok(EmailManager {
            smtp_transport: mailer,
            email: smtp_email.to_string(),
        })
    }
    pub fn send_reset_password_email(
        &self,
        email: &str,
        url: &str,
        reset_password_token: &str,
        recipient_name: &str,
    ) -> Result<(), EmailManagerError> {
        let from_address: Address = self.email.parse()?;
        let to_address: Address = email.parse()?;

        let subject = "Passwort zurücksetzen";
        let reset_link = format!(
            "{}/reset-password?c={}&e={}",
            url,
            urlencoding::encode(reset_password_token),
            urlencoding::encode(email)
        );
        let email_body = format!(
            r#"<!DOCTYPE html>
            <html>
              <head>
                <style>
                  /* General Styles */
                  body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                  }}

                  .email-container {{
                    background-color: white;
                    margin: 0;
                    padding: 20px;
                    max-width: 600px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                  }}

                  /* Logo Section */
                  .header {{
                    text-align: left;
                    font-size: 1.25rem;
                    font-weight: 600;
                  }}

                  .header img {{
                    width: 120px;
                  }}

                  /* Main content */
                  .content {{
                    margin-top: 20px;
                  }}

                  .content h1 {{
                    font-size: 20px;
                    color: #333;
                  }}

                  .content p {{
                    font-size: 16px;
                    color: #444;
                    line-height: 1.6;
                  }}

                  /* Reset Button */
                  .reset-button {{
                    display: inline-block;
                    background-color: #11253e;
                    color: #fff !important;
                    padding: 15px 20px;
                    text-decoration: none;
                    font-size: 16px;
                    border-radius: 4px;
                    margin-top: 20px;
                    margin-bottom: 10px;
                  }}
                </style>
              </head>
              <body>
                <div class="email-container">
                  <!-- Header with Logo -->
                  <div class="header">
                    CouchTec
                  </div>

                  <!-- Email Content -->
                  <div class="content">
                    <p>Hey {recipient_name},</p>
                    <p>Wir haben eine Anfrage erhalten, dein Passwort zurückzusetzen.</p>
                    <p>Wenn du die Anfrage nicht gestellt haben, ignoriere diese Nachricht einfach. Ansonsten kannst du dein Passwort zurücksetzen, indem du auf die Schaltfläche unten klickst.</p>

                    <!-- Reset Button -->
                    <a href="{reset_link}" class="reset-button">Passwort zurücksetzen</a>

                    <p>Danke,<br>Das CouchTec Team</p>
                  </div>
                </div>
              </body>
            </html>"#,
            recipient_name = recipient_name,
            reset_link = reset_link
        );

        let email = Message::builder()
            .from(from_address.into())
            .to(to_address.into())
            .subject(subject)
            .header(header::ContentType::TEXT_HTML)
            .body(email_body.to_string())?;

        self.smtp_transport.send(&email)?;
        Ok(())
    }

    pub fn send_verify_email(
        &self,
        email: &str,
        url: &str,
        verification_token: &str,
        recipient_name: &str,
    ) -> Result<(), EmailManagerError> {
        let from_address: Address = self.email.parse()?;
        let to_address: Address = email.parse()?;

        let subject = "E-Mail verifizieren";
        let reset_link = format!(
            "{}?vc={}&e={}",
            url,
            urlencoding::encode(verification_token),
            urlencoding::encode(email)
        );
        let email_body = format!(
            r#"<!DOCTYPE html>
            <html>
              <head>
                <style>
                  /* General Styles */
                  body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                  }}

                  .email-container {{
                    background-color: white;
                    margin: 0;
                    padding: 20px;
                    max-width: 600px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                  }}

                  /* Logo Section */
                  .header {{
                    text-align: left;
                    font-size: 1.25rem;
                    font-weight: 600;
                  }}

                  .header img {{
                    width: 120px;
                  }}

                  /* Main content */
                  .content {{
                    margin-top: 20px;
                  }}

                  .content h1 {{
                    font-size: 20px;
                    color: #333;
                  }}

                  .content p {{
                    font-size: 16px;
                    color: #444;
                    line-height: 1.6;
                  }}

                  /* Reset Button */
                  .reset-button {{
                    display: inline-block;
                    background-color: #11253e;
                    color: #fff !important;
                    padding: 15px 20px;
                    text-decoration: none;
                    font-size: 16px;
                    border-radius: 4px;
                    margin-top: 20px;
                    margin-bottom: 10px;
                  }}
                </style>
              </head>
              <body>
                <div class="email-container">
                  <!-- Header with Logo -->
                  <div class="header">
                    CouchTec
                  </div>

                  <!-- Email Content -->
                  <div class="content">
                    <p>Hey {recipient_name},</p>
                    <p>Wir haben eine Anfrage erhalten, Ihre E-Mail zu verifizieren.</p>
                    <p>Wenn du die Anfrage nicht gestellt haben, ignoriere diese Nachricht einfach. Ansonsten kannst du deine E-Mail verifizieren, indem du auf die Schaltfläche unten klickst.</p>

                    <!-- Reset Button -->
                    <a href="{reset_link}" class="reset-button">E-Mail verifizieren</a>

                    <p>Danke,<br>Das CouchTec Team</p>
                  </div>
                </div>
              </body>
            </html>"#,
            recipient_name = recipient_name,
            reset_link = reset_link
        );

        let email = Message::builder()
            .from(from_address.into())
            .to(to_address.into())
            .subject(subject)
            .header(header::ContentType::TEXT_HTML)
            .body(email_body.to_string())?;

        self.smtp_transport.send(&email)?;
        Ok(())
    }
}
