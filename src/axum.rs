use crate::str_to_c_char;
use crate::Inigo;
use crate::SidecarConfig;
use crate::CREATE;
use apollo_router::graphql;
use axum::{
    body::Body,
    http::Request,
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use std::ptr::null;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
pub struct InigoLayer {
    handler: usize,
    path: &'static str,
}

impl InigoLayer {
    pub fn new(token: &str, schema: &str, path: &'static str) -> Self {
        InigoLayer {
            handler: CREATE(&SidecarConfig {
                debug: false,
                service: null(),
                token: str_to_c_char(token),
                schema: str_to_c_char(schema),
                name: str_to_c_char("inigo-rs"),
                runtime: null(),
                egress_url: null(),
                gateway: null(),
                disable_response_data: true,
            }),
            path,
        }
    }
}

impl<S> Layer<S> for InigoLayer {
    type Service = InigoMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InigoMiddleware {
            handler: self.handler.clone(),
            inner,
            path: self.path,
        }
    }
}

#[derive(Clone)]
pub struct InigoMiddleware<S> {
    handler: usize,
    inner: S,
    path: &'static str,
}

impl<S> Service<Request<Body>> for InigoMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();

        let inigo = Inigo::new(self.handler.clone());
        let path = self.path;

        Box::pin(async move {
            if request.uri().path() != path {
                return Ok(inner.call(request).await?);
            }

            let content_type = request.headers().get("Content-Type");
            if content_type.is_none() || content_type.unwrap() != "application/json" {
                let future = inner.call(request);
                let response: Response = future.await?;
                return Ok(response);
            }

            let headers = request.headers().clone();
            let (mut parts, body) = request.into_parts();
            let bytes = hyper::body::to_bytes(body).await.unwrap();

            let mut req: graphql::Request = serde_json::from_slice(&bytes).unwrap();
            let resp = inigo.process_request("", &mut req, &headers);
            if resp.is_some() {
                let src: String = serde_json::to_string(&resp).unwrap();
                return Ok(Response::builder()
                    .body(Body::from(src))
                    .unwrap()
                    .into_response());
            }

            let bytes = serde_json::to_string(&req).unwrap();

            parts.headers.remove("content-length");
            let future = inner.call(Request::from_parts(parts, Body::from(bytes)));

            let response: Response = future.await?;

            let (mut parts, body) = response.into_parts();
            let bytes = hyper::body::to_bytes(body).await.unwrap();

            let mut resp: graphql::Response = serde_json::from_slice(&bytes).unwrap();
            inigo.process_response(&mut resp);
            let bytes = serde_json::to_string(&resp).unwrap();
            parts.headers.remove("content-length");

            Ok(Response::from_parts(parts, Body::from(bytes)).into_response())
        })
    }
}
