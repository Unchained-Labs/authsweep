//! An axum control plane, written in the shapes rustfmt actually produces.
//!
//! Modelled on a real service: chained method routers, routes wrapped across
//! lines because the handler name is long, a fully-qualified `axum::routing::`
//! helper, `{id}` captures, and a nested router built by a separate function.

use axum::{
    extract::{Path, State},
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;

/// A guard extractor. Its *type* is what marks the route as checked.
pub struct AuthUser(pub String);

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        // Two exposures on one line. Each gets its own handler.
        .route("/v1/projects", post(create_project).get(list_projects))
        .route(
            "/v1/workspaces/{id}/command",
            post(run_workspace_command),
        )
        .route("/v1/workspaces/{id}/file", get(read_workspace_file))
        .route("/v1/jobs/{id}", get(get_job))
        .route("/v1/queue/{id}", axum::routing::patch(update_queue_position))
        .route("/v1/reports/{id}/export", get(export_report))
        // A path with braces inside a raw string, which is what breaks a
        // brace-counting scanner that does not know about string literals.
        .route(r#"/v1/templates/{name}"#, get(get_template))
        .route("/v1/legacy", get(legacy_handler))
        .nest("/admin", admin_router())
        .merge(billing_router())
        .with_state(state)
        // Neither of these is an authorization check, and a scanner that reads
        // them as one reports a clean bill of health over the whole file.
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer())
}

/// Everything on this router sits behind one guard.
fn admin_router() -> Router {
    Router::new()
        .route("/users/{id}", axum::routing::delete(delete_user))
        .route("/flags", post(set_flags))
        .route_layer(middleware::from_fn(require_admin))
}

/// This one has no router-level guard; the guard is on the handler instead.
fn billing_router() -> Router {
    Router::new()
        .route("/v1/billing/invoices", get(list_invoices))
        .route("/v1/billing/charge", post(create_charge))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics() -> String {
    String::new()
}

async fn create_project(State(_s): State<AppState>) -> StatusCode {
    StatusCode::CREATED
}

async fn list_projects(State(_s): State<AppState>) -> Json<Vec<Project>> {
    Json(vec![])
}

async fn run_workspace_command(Path(_id): Path<String>) -> StatusCode {
    StatusCode::OK
}

async fn read_workspace_file(Path(_id): Path<String>) -> String {
    String::new()
}

async fn get_job(Path(_id): Path<String>) -> StatusCode {
    StatusCode::OK
}

async fn update_queue_position(Path(_id): Path<String>) -> StatusCode {
    StatusCode::OK
}

async fn export_report(Path(_id): Path<String>) -> String {
    String::new()
}

async fn get_template(Path(_name): Path<String>) -> String {
    String::new()
}

/// Not a finding: there is nothing here yet.
async fn legacy_handler() -> StatusCode {
    todo!("dropped in the v2 rewrite")
}

async fn delete_user(Path(_id): Path<String>) -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn set_flags() -> StatusCode {
    StatusCode::OK
}

/// Guarded by its signature: the `AuthUser` extractor runs before the body does.
async fn list_invoices(AuthUser(_caller): AuthUser) -> Json<Vec<Invoice>> {
    Json(vec![])
}

/// Not guarded. Takes money, and reads a caller id out of the *body*, which is
/// not the same thing as verifying it.
async fn create_charge(Json(_body): Json<ChargeRequest>) -> StatusCode {
    StatusCode::ACCEPTED
}

fn describe<'a>(label: &'a str) -> &'a str {
    label
}
