//! Rocket, where the prefix is applied at `mount()` and the guard is a request
//! guard in the handler signature.

#[macro_use]
extern crate rocket;

use rocket::serde::json::Json;

/// A request guard. Rocket runs it before the handler, so its presence in the
/// signature *is* the authorization check.
pub struct AdminClaims {
    pub subject: String,
}

#[get("/jobs/<id>")]
fn get_job(id: &str) -> Json<Job> {
    Json(Job::default())
}

#[post("/jobs/<id>/cancel")]
fn cancel_job(id: &str) -> Status {
    Status::Ok
}

#[delete("/tenants/<id>")]
fn delete_tenant(id: &str, claims: AdminClaims) -> Status {
    Status::NoContent
}

#[get("/ping")]
fn ping() -> &'static str {
    "pong"
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/api/v1", routes![get_job, cancel_job, ping])
        .mount("/internal", routes![delete_tenant])
}
