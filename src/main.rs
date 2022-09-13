use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

mod decryptor;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body(
        r###"<doctype html>
<head>
</head>
<body>
  <form mthod="post" action="challenge">
    Passphrase : <input type="text" name="passphrase">
    Challenge : <textarea name="challenge"></textarea>
    <inpyt type="submit">
  </form>
</body>
"###,
    )
}

#[post("/challenge")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(hello).service(echo))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
