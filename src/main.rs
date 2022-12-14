use crate::decryptor::decrypt;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use sequoia_openpgp::crypto::Password;
use serde::Deserialize;

mod decryptor;
mod keys;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body(
        r###"<!doctype html>
<head>
</head>
<body>
  <form method="post" action="/">
    <label for="passphrase">Passphrase : </label><input type="text" id="passphrase" name="passphrase"><br>
    <label for"challenge">Challenge : </label><textarea id="challenge" name="challenge" rows="5" cols="33"></textarea><br>
    <input type="submit">
  </form>
</body>
"###,
    )
}

#[derive(Deserialize)]
struct FormData {
    passphrase: String,
    challenge: String,
}

#[post("/")]
async fn echo(mut form: web::Form<FormData>) -> impl Responder {
    let encrypted_password = Password::from(form.passphrase.clone());
    form.passphrase.clear();
    match decrypt(form.challenge.clone(), encrypted_password) {
        Ok(i) => HttpResponse::Ok().body(i),
        Err(..) => HttpResponse::Ok().body("Cannot decrypt message"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(hello).service(echo))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
