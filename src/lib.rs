pub mod axum;
pub mod registry;
pub mod ffi;
mod tests;
mod proxy_service;
mod parser;

#[macro_use]
extern crate lazy_static;

use std::env;
use std::ptr::null;
use std::sync::Mutex;
use std::str::FromStr;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use http::{HeaderName, HeaderValue};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use futures::FutureExt;

use serde::Deserialize;
use multimap::MultiMap;
use schemars::JsonSchema;
use tower::{BoxError, ServiceBuilder, ServiceExt};
use tokio::task;

use apollo_router::graphql;
use apollo_router::Endpoint;
use apollo_router::ListenAddr;
use apollo_router::services::router;
use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::{Plugin, PluginInit};
use apollo_router::services::{subgraph, supergraph};

use crate::ffi::Inigo;

#[derive(Debug)]
pub struct Middleware {
    pub handler: usize,
    pub enabled: bool,
    pub subgraphs_analytics: bool,
    pub trace_header: String,
    pub auto_download_library: bool,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct Conf {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    service: String,
    #[serde(default)]
    token: String,
    #[serde(default = "default_true")]
    subgraphs_analytics: bool,
    #[serde(default = "default_trace_header")]
    trace_header: String,
    #[serde(default)]
    auto_download_library: bool,
}

lazy_static! {
    static ref SINGLETON: Mutex<Option<Middleware>> = Mutex::new(None);
}

#[async_trait::async_trait]
impl Plugin for Middleware {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        if !init.config.enabled {
            return Ok(Middleware {
                handler: 0,
                enabled: false,
                subgraphs_analytics: false,
                trace_header: init.config.trace_header,
                auto_download_library: init.config.auto_download_library,
            });
        }

        if init.config.auto_download_library {
            task::spawn_blocking(|| ffi::download_library()).await.unwrap();
        }

        let mut singleton = SINGLETON.lock().unwrap();
        if singleton.is_some() {
            let middleware = singleton.as_ref().unwrap().clone();
            ffi::update_schema(middleware.handler, init.supergraph_sdl.as_str());
            return Ok(middleware);
        }

        let mut token = init.config.token;
        if token.is_empty() {
            if let Ok(key) = env::var("INIGO_SERVICE_TOKEN") {
                token = key;
            }
        }

        let cfg = ffi::SidecarConfig {
            debug: false,
            service: ffi::to_raw(&init.config.service),
            token: ffi::to_raw(&token),
            schema: ffi::to_raw(init.supergraph_sdl.as_str()),
            name: ffi::to_raw("inigo-rs"),
            runtime: null(),
            egress_url: null(),
            gateway: null(),
            disable_response_data: true,
        };

        let middleware = Middleware {
            handler: ffi::create(&cfg).expect("libinigo"),
            enabled: init.config.enabled,
            subgraphs_analytics: init.config.subgraphs_analytics,
            trace_header: init.config.trace_header.clone(),
            auto_download_library: init.config.auto_download_library,
        };

        ffi::free_raw(cfg.service);
        ffi::free_raw(cfg.token);
        ffi::free_raw(cfg.schema);
        ffi::free_raw(cfg.name);

        *singleton = Some(middleware.clone());

        Ok(middleware)
    }

    fn router_service(&self, service: router::BoxService) -> router::BoxService {
        let handler = self.handler.clone();
        let trace = self.trace_header.clone();

        async fn process_get(handler: usize, mut request: router::Request) -> Result<ControlFlow<router::Response, router::Request>, BoxError> {

            let query = request.router_request.uri().query().unwrap_or("").to_string();
            let headers = request.router_request.headers();

            let req_gql = match graphql::Request::from_urlencoded_query(query) {
                Ok(req) => req,
                Err(_) => {
                    return Ok(ControlFlow::Break(router::Response::from(
                        http::Response::builder()
                            .status(400)
                            .header("content-type", "application/json")
                            .body(String::from("invalid query"))
                            .unwrap()
                    )));
                }
            };
            
            let req_str = match serde_json::to_string(&req_gql) {
                Ok(json) => json,
                Err(_) => {
                    return Ok(ControlFlow::Break(router::Response::from(
                        http::Response::builder()
                            .status(400)
                            .header("content-type", "application/json")
                            .body(String::from("invalid JSON in query"))
                            .unwrap()
                    )));
                }
            };

            let mut req_mut_data: Option<Vec<u8>> = None;
            let mut scalars: Option<std::collections::HashSet<String>> = None;
            let mut resp_data: Option<Vec<u8>> = None;
    
            let handle = ffi::process_request(
                handler,
                None,
                req_str.as_bytes(),
                headers,
                &mut req_mut_data,
                &mut scalars,
                &mut resp_data
            );

            let _ = request.context.insert("processed", handle);

            if scalars.is_some() {
                let _ = request.context.insert("scalars", scalars.unwrap());
            }

            if resp_data.is_some() {
                return Ok(ControlFlow::Break(router::Response::from(
                    http::Response::builder()
                        .body(body_from_bytes(resp_data.unwrap()))
                        .unwrap(),
                )));
            }

            if req_mut_data.is_some() {
                let req_mut_gql: graphql::Request = serde_json::from_slice(&req_mut_data.unwrap()).unwrap();

                // parse will fail bc base is missing, adding localhost here to bypass RelativeUrlWithoutBase error
                let original_url = format!("http://localhost{}", request.router_request.uri());
                let original_url: url::Url = original_url.parse()?;

                let query = original_url.query_pairs().filter(|(name, _)| {
                    name != "query" && name != "extensions"
                });

                let mut new_url = original_url.clone();
                new_url.query_pairs_mut().clear().extend_pairs(query);

                if let Some(query) = req_mut_gql.query {
                    new_url.query_pairs_mut().append_pair("query", &query);
                }

                if !req_mut_gql.extensions.is_empty() {
                    new_url.query_pairs_mut().append_pair(
                        "extensions",
                        &serde_json::to_string(&req_mut_gql.extensions).unwrap(),
                    );
                }

                if !req_mut_gql.variables.is_empty() {
                    new_url.query_pairs_mut().append_pair(
                        "variables",
                        &serde_json::to_string(&req_mut_gql.variables).unwrap(),
                    );
                }

                if let Some(operation_name) = req_mut_gql.operation_name {
                    new_url.query_pairs_mut().append_pair("operationName", &operation_name);
                }

                *request.router_request.uri_mut() = new_url
                    .to_string()
                    .strip_prefix("http://localhost")
                    .unwrap()
                    .parse()?;
            }

            Ok(ControlFlow::Continue(request))
        }

        async fn process_post(handler: usize, mut request: router::Request) -> Result<ControlFlow<router::Response, router::Request>, BoxError> {
            let data = request.router_request.body_mut().collect().await?.to_bytes();
            let headers = request.router_request.headers();

            let mut req_mut_data: Option<Vec<u8>> = None;
            let mut scalars: Option<std::collections::HashSet<String>> = None;
            let mut resp_data: Option<Vec<u8>> = None;
    
            let handle = ffi::process_request(
                handler,
                None,
                &data,
                headers,
                &mut req_mut_data,
                &mut scalars,
                &mut resp_data
            );

            let _ = request.context.insert("processed", handle);

            if resp_data.is_some() {
                return Ok(ControlFlow::Break(router::Response::from(
                    http::Response::builder()
                        .body(body_from_bytes(resp_data.unwrap()))
                        .unwrap(),
                )));
            }

            if req_mut_data.is_some() {
                *request.router_request.body_mut() = body_from_bytes(req_mut_data.unwrap());
                return Ok(ControlFlow::Continue(request));
            }

            if scalars.is_some() {
                let _ = request.context.insert("scalars", scalars.unwrap());
            }

            *request.router_request.body_mut() = body_from_bytes(data);
            Ok(ControlFlow::Continue(request))
        }
    
        ServiceBuilder::new()
            .checkpoint_async(move |mut request: router::Request| {
                let trace = trace.clone();

                async move {
                    let method = request.router_request.method().clone();

                    request
                        .router_request
                        .headers_mut()
                        .entry(HeaderName::from_str(&trace).unwrap())
                        .or_insert(
                            HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap(),
                        );

                    // Handle GET request
                    if method == http::Method::GET {
                        return process_get(handler, request).await;
                    }

                    // Handle POST request
                    if method == http::Method::POST {
                        return process_post(handler, request).await;
                    }

                    Ok(ControlFlow::Continue(request))
                }.boxed()
            })
            .buffered()
            .service(service)
            .boxed()
    }

    fn subgraph_service(&self, _name: &str, service: subgraph::BoxService) -> subgraph::BoxService {
        if !self.enabled || !self.subgraphs_analytics {
            return service;
        }

        let inigo = Inigo::new(self.handler.clone());
        let name = _name.to_owned();
        
        let process_req_fn = |i: Inigo| {
            move |mut req: subgraph::Request| {
                let headers = &req.subgraph_request.headers().clone();
                let resp = i.process_request(&name, req.subgraph_request.body_mut(), headers);

                let traceparent = req.subgraph_request.body().extensions.get("traceparent");
                if traceparent.is_some() {
                    let traceparent_val = traceparent.unwrap().clone();
                    req.subgraph_request.headers_mut().insert(
                        "traceparent",
                        HeaderValue::from_str(traceparent_val.as_str().unwrap()).unwrap(),
                    );
                }

                if resp.is_none() {
                    return Ok(ControlFlow::Continue(req));
                }

                let response = resp.unwrap();

                return Ok(ControlFlow::Break(
                    subgraph::Response::builder()
                    .data(response.data.unwrap_or_default())
                    .errors(response.errors)
                    .extensions(response.extensions)
                    .context(req.context)
                    .subgraph_name(&name)
                    .build()
                ));
            }
        };

        let process_resp_fn = |i: Inigo| {
            move |mut resp: subgraph::Response| {
                i.process_response(resp.response.body_mut());
                return resp;
            }
        };

        ServiceBuilder::new()
            .checkpoint(process_req_fn(inigo.clone()))
            .map_response(process_resp_fn(inigo.clone()))
            .service(service)
            .boxed()
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        if !self.enabled {
            return service;
        }

        let inigo = Inigo::new(self.handler.clone());

        let process_req_fn = move |mut req: supergraph::Request| {
            let traceparent = req.supergraph_request.body().extensions.get("traceparent");
            if traceparent.is_some() {
                let traceparent_val = traceparent.unwrap().clone();
                req.supergraph_request.headers_mut().insert(
                    "traceparent",
                    HeaderValue::from_str(traceparent_val.as_str().unwrap()).unwrap(),
                );
            }

            return Ok(ControlFlow::Continue(req));
        };

        let process_resp_fn = |i: Inigo| {
            move |response: supergraph::Response| {
                i.set_handle(response.context.get("processed").unwrap().unwrap_or_default());
                i.set_scalars(response.context.get("scalars").unwrap().unwrap_or_default());

                return response.map_stream(move |mut resp: graphql::Response| {
                    i.process_response(&mut resp);
                    return resp;
                });
            }
        };

        ServiceBuilder::new()
            .checkpoint(process_req_fn)
            .map_response(process_resp_fn(inigo))
            .service(service)
            .boxed()
    }

    fn web_endpoints(&self) -> MultiMap<ListenAddr, Endpoint> {
        let mut endpoints = MultiMap::new();
        let pass_through_url = env::var_os("INIGO_PASS_THROUGH_URL");
        let listen_addr = env::var_os("APOLLO_ROUTER_LISTEN_ADDRESS");
        if pass_through_url.is_none() || listen_addr.is_none() {
            return endpoints;
        }

        let web_endpoint = Endpoint::from_router_service(
            "/*key".to_string(),
            proxy_service::ProxyService {
                url: pass_through_url
                    .unwrap()
                    .into_string()
                    .unwrap()
                    .parse()
                    .unwrap(),
            }
            .boxed(),
        );

        let socket_addr: SocketAddr = listen_addr.unwrap().into_string().unwrap().parse().unwrap();
        endpoints.insert(ListenAddr::from(socket_addr), web_endpoint);
        endpoints
    }
}

impl Clone for Middleware {
    fn clone(&self) -> Middleware {
        Middleware {
            handler: self.handler,
            enabled: self.enabled,
            subgraphs_analytics: self.subgraphs_analytics,
            trace_header: self.trace_header.clone(),
            auto_download_library: self.auto_download_library,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_trace_header() -> String {
    "Inigo-Router-TraceID".to_string()
}

fn body_from_bytes<T: Into<Bytes>>(chunk: T) -> UnsyncBoxBody<Bytes, axum_core::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}