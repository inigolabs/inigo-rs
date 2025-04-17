use inigo_rs::poem::InigoLayer;
use async_graphql::http::GraphiQLSource;
use async_graphql_poem::GraphQL;
use poem::{get, handler, listener::TcpListener, web::Html, EndpointExt, IntoResponse, Route, Server};

#[handler]
async fn graphiql() -> impl IntoResponse {
    Html(GraphiQLSource::build().endpoint("/").finish())
}

#[tokio::main]
async fn main() {
    let schema = starwars::schema().unwrap();
    let sdl = &schema.sdl();

    let inigo = InigoLayer::new(
        &std::env::var("INIGO_SERVICE_TOKEN").expect("env variable INIGO_SERVICE_TOKEN"), 
        sdl, "/");

    let app = Route::new()
    .at("/", 
        get(graphiql).
        post(GraphQL::new(schema)))
    .with(inigo);

    println!("GraphiQL IDE: http://localhost:4000");
    Server::new(TcpListener::bind("127.0.0.1:4000"))
        .run(app)
        .await
        .unwrap();
}
