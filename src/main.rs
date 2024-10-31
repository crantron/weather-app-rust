use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, errors::ErrorKind};
use jsonwebtoken::errors::Error as JwtError;

mod jwt;
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login_handler(req: web::Json<LoginRequest>) -> impl Responder {
    let secret = "key";

    if req.username == "admin" && req.password == "password" {
        let claims = Claims {
            sub: req.username.clone(),
            exp: 10000000000, // Example expiration time
        };

        match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())) {
            Ok(token) => HttpResponse::Ok().json(token),
            Err(_) => HttpResponse::InternalServerError().finish(),
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

async fn protected_handler(token: String) -> impl Responder {
    let secret = "key";

    match decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &Validation::default()) {
        Ok(data) => HttpResponse::Ok().body(format!("Welcome {}", data.claims.sub)),
        Err(err) => match *err.kind() {
            ErrorKind::ExpiredSignature => HttpResponse::Unauthorized().body("Token expired"),
            _ => HttpResponse::InternalServerError().finish(),
        },
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/login", web::post().to(login_handler))
            .route("/protected", web::get().to(protected_handler))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}