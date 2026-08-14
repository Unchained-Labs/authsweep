//! actix-web, in the attribute-macro style most actix services are written in.
//!
//! Two things here that a `.route(` scanner alone would miss entirely: the path
//! lives in an attribute above the handler, and the prefix lives in a
//! `web::scope()` far away from it.

use actix_web::{delete, get, post, web, App, HttpResponse, HttpServer};
use actix_web_httpauth::middleware::HttpAuthentication;

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[post("/uploads")]
async fn create_upload(body: web::Bytes) -> HttpResponse {
    HttpResponse::Created().finish()
}

#[delete("/keys/{id}")]
async fn revoke_key(path: web::Path<String>) -> HttpResponse {
    HttpResponse::NoContent().finish()
}

#[get("/secrets/{id}")]
async fn read_secret(path: web::Path<String>) -> HttpResponse {
    HttpResponse::Ok().finish()
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(health)
        .service(create_upload)
        // Everything in this scope is behind bearer auth.
        .service(
            web::scope("/admin")
                .wrap(HttpAuthentication::bearer(validate_bearer))
                .service(revoke_key),
        )
        // This one is not.
        .service(web::scope("/v1").service(read_secret))
        .route("/v1/ping", web::get().to(ping))
        .route("/v1/accounts/{id}/close", web::post().to(close_account));
}

async fn ping() -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn close_account(path: web::Path<String>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
