use async_graphql::{http::GraphiQLSource, EmptyMutation, EmptySubscription, Schema};
use async_graphql_axum::GraphQL;
use axum::{
    response::{self, IntoResponse},
    routing::get,
    Router,
    Server,
};
use starwars::{QueryRoot, StarWars};
use inigo_rs::axum::InigoLayer;

async fn graphiql() -> impl IntoResponse {
    response::Html(GraphiQLSource::build().endpoint("/").finish())
}

#[tokio::main]
async fn main() {
     let schema = Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
        .data(StarWars::new())
        .finish();

    let sdl = &schema.sdl();
    let app = Router::new()
        .route("/", get(graphiql).post_service(GraphQL::new(schema)))
        .layer(InigoLayer::new(&std::env::var("INIGO_SERVICE_TOKEN").
            expect("env variable INIGO_SERVICE_TOKEN"), 
            sdl, "/"));

    println!("INFO  GraphQL endpoint exposed at http://127.0.0.1:4000/ 🚀");

    Server::bind(&"127.0.0.1:4000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}