use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};

mod config;
mod vulnerable;

#[derive(Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Deserialize)]
struct CreateItem {
    name: String,
    description: Option<String>,
}

#[derive(Serialize)]
struct Item {
    id: u64,
    name: String,
    description: String,
}

#[get("/health")]
async fn health_check() -> impl Responder {
    let response = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    HttpResponse::Ok().json(response)
}

#[get("/items")]
async fn list_items() -> impl Responder {
    let items = vec![
        Item {
            id: 1,
            name: "Widget".to_string(),
            description: "A sample widget".to_string(),
        },
        Item {
            id: 2,
            name: "Gadget".to_string(),
            description: "A sample gadget".to_string(),
        },
    ];
    HttpResponse::Ok().json(items)
}

#[post("/items")]
async fn create_item(item: web::Json<CreateItem>) -> impl Responder {
    let new_item = Item {
        id: 3,
        name: item.name.clone(),
        description: item.description.clone().unwrap_or_default(),
    };
    HttpResponse::Created().json(new_item)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server on http://127.0.0.1:8080");

    env_logger::init();

    HttpServer::new(|| {
        App::new()
            .service(health_check)
            .service(list_items)
            .service(create_item)
            // Intentionally vulnerable endpoints for CodeQL demo
            .service(vulnerable::search_items)
            .service(vulnerable::greet_user)
            .service(vulnerable::read_file)
            .service(vulnerable::fetch_url)
            .service(vulnerable::logged_search)
            .service(vulnerable::login)
            .service(vulnerable::hash_password)
            .service(vulnerable::regex_search)
            .service(vulnerable::send_report)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_web::test]
    async fn test_health_check() {
        let app = test::init_service(App::new().service(health_check)).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_list_items() {
        let app = test::init_service(App::new().service(list_items)).await;
        let req = test::TestRequest::get().uri("/items").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
