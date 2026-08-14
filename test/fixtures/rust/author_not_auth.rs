//! Regression fixture: PascalCase types that merely *start* like "auth".
//!
//! The Python counterpart of this file is `fastapi/di_not_auth.py`, where
//! `Depends(get_service)` was read as an authorization guard and authsweep
//! reported a clean bill of health over two open endpoints. Rust has the same
//! trap with a different spelling: `Author`, `Authored` and `AuthorMeta` all
//! begin with the four letters that matter, and a `\bauth/i` pattern with a lazy
//! prefix will happily match them.
//!
//! Every route in this file is unguarded. If any of them is prefiltered, the
//! guard pattern has grown too broad and the tool is back to going quiet on
//! real exposure.

use axum::{routing::{get, post}, Json, Router};

/// A blog post's author. Not a guard.
pub struct Author {
    pub name: String,
}

/// Editorial metadata. Not a guard.
pub struct AuthorMeta {
    pub authored_at: String,
}

pub fn app() -> Router {
    Router::new()
        .route("/v1/posts/{id}/author", post(set_author))
        .route("/v1/authors/{id}/payouts", post(create_payout))
        .route("/v1/authored", get(list_authored))
}

async fn set_author(Json(_a): Json<Author>) -> StatusCode {
    StatusCode::OK
}

async fn create_payout(_meta: AuthorMeta) -> StatusCode {
    StatusCode::ACCEPTED
}

async fn list_authored(_meta: AuthorMeta) -> Json<Vec<Author>> {
    Json(vec![])
}
