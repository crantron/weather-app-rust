use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

impl Claims {
    fn new(user_id: &str, expiration: usize) -> Self {
        Self {
            sub: user_id.to_owned(),
            exp: expiration,
        }
    }
}

pub fn generate_jwt(user_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() + 3600;

    let claims = Claims::new(user_id, expiration as usize);

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))?;
    Ok(token)
}

pub fn verify_jwt(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS512),
    )?;
    Ok(token_data.claims)
}



