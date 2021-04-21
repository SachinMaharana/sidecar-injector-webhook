use actix_web::{get, http, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::anyhow;
use anyhow::Result;
use k8s_openapi::apimachinery::pkg::apis::meta::v1;

use kube::api::{
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
    DynamicObject,
};
use rustls::internal::pemfile::{certs, rsa_private_keys};
use rustls::{NoClientAuth, ServerConfig};
use serde::Deserialize;
use serde_json::{json, Value};
use std::convert::TryInto;
use std::fs::File;
use std::io::BufReader;
use tracing::{debug, error, info, warn};
use tracing_subscriber::filter::EnvFilter;

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok()
        .header(http::header::CONTENT_TYPE, "application/json")
        .json(json!({"message": "ok"}))
}

#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
    std::env::set_var("RUST_LOG", "actix_web=warn,sidecar_injector_webhook=debug");
    let filter = EnvFilter::from_default_env();

    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!("Started http server: 0.0.0.0:8443");
    let mut config = ServerConfig::new(NoClientAuth::new());
    let cert_file = &mut BufReader::new(File::open("./certs/serverCert.pem")?);
    let key_file = &mut BufReader::new(File::open("./certs/serverKey.pem")?);
    let cert_chain = certs(cert_file).expect("error in cert");
    let mut keys = rsa_private_keys(key_file).expect("error in key");
    config.set_single_cert(cert_chain, keys.remove(0))?;

    HttpServer::new(|| App::new().service(handle_mutate).service(health))
        .bind_rustls("0.0.0.0:8443", config)?
        .run()
        .await?;
    Ok(())
}

fn mutation_required(ignored_namespace: String, metadata: &DynamicObject) {}

#[post("/mutate")]
async fn handle_mutate(
    reqst: HttpRequest,
    body: web::Json<AdmissionReview<DynamicObject>>,
) -> impl Responder {
    info!(
        "request recieved: method={:?}, uri={}",
        reqst.method(),
        reqst.uri(),
    );

    if let Some(content_type) = reqst.head().headers.get("content-type") {
        if content_type != "application/json" {
            let msg = format!("invalid content-type: {:?}", content_type);
            warn!("warn: {}, code: {}", msg, http::StatusCode::BAD_REQUEST);
            return HttpResponse::BadRequest().json(msg);
        }
    }

    let req: AdmissionRequest<_> = match body.into_inner().try_into() {
        Ok(req) => req,
        Err(err) => {
            error!("invalid request: {}", err.to_string());
            return HttpResponse::InternalServerError()
                .json(&AdmissionResponse::invalid(err.to_string()).into_review());
        }
    };

    let resp = AdmissionResponse::from(&req);

    let obj = match req
        .object
        .ok_or_else(|| anyhow!("could not get object from the request body"))
    {
        Ok(obj) => obj,
        Err(e) => return HttpResponse::InternalServerError().json(e.to_string()),
    };
    info!(
        "admission review for kind: {:?}, namespace: {:?}, name: {:?}, operation: {:?}",
        obj.clone().types.unwrap_or_default().kind,
        &req.namespace.as_ref().unwrap_or(&"unknown".to_owned()),
        obj.metadata.name.as_ref().unwrap_or(&"unknown".to_owned()),
        &req.operation
    );

    let pod = &obj;

    if !mutation_required(ignoredNamespace, &pod.metadata) {}

    HttpResponse::Ok().json(resp.into_review())
}
