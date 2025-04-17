use std::ptr::null;
use poem::{ Endpoint, Body, IntoResponse, Middleware, Request, Response, Result };
use crate::ffi::*;
use apollo_router::graphql;

#[derive(Clone)]
pub struct InigoLayer {
    handler: usize,
    path: &'static str,
}

impl InigoLayer {
    pub fn new(token: &str, schema: &str, path: &'static str) -> Self {
        tokio::task::block_in_place(|| {
            download_library();
        });

        let handle = create(&SidecarConfig {
            debug: false,
            service: null(),
            token: to_raw(token),
            schema: to_raw(schema),
            name: to_raw("inigo-rs"),
            runtime: null(),
            egress_url: null(),
            gateway: null(),
            disable_response_data: true,
        });

        InigoLayer {
            handler: handle.unwrap(),
            path,
        }
    }
}

impl<E: Endpoint> Middleware<E> for InigoLayer {
    type Output = InigoLayerImpl<E>;

    fn transform(&self, ep: E) -> Self::Output {
        InigoLayerImpl {
            inner: ep,
            handler: self.handler,
            path: self.path,
        }
    }
}

#[derive(Clone)]
pub struct InigoLayerImpl<S> {
    inner: S,
    handler: usize,
    path: &'static str,
}

impl<E: Endpoint> Endpoint for InigoLayerImpl<E> {
    type Output = Response;

    async fn call(&self, request: Request) -> Result<Self::Output> {
        if request.uri().path() != self.path {
            return Ok(self.inner.call(request).await?.into_response());
        }

        let content_type = request.headers().get("Content-Type");
        if content_type.is_none() || content_type.unwrap() != "application/json" {
            let future = self.inner.call(request);
            let response: Response = future.await?.into_response();
            return Ok(response);
        }

        let headers = request.headers().clone();
        let (mut parts, body) = request.into_parts();
        let bytes =  body.into_bytes().await.unwrap();

        let inigo = Inigo::new(self.handler.clone());
        let mut req: graphql::Request = serde_json::from_slice(&bytes).unwrap();
        let resp = inigo.process_request("", &mut req, &headers);
        if resp.is_some() {
            let src: String = serde_json::to_string(&resp).unwrap();
            return Ok(Response::builder()
                .body(Body::from(src))
                .into_response());
        }

        let bytes = serde_json::to_string(&req).unwrap();
        parts.headers.remove("content-length");

        let future = self.inner.call(Request::from_parts(parts, Body::from(bytes))).into_future();
        let response: Response = future.await?.into_response();

        let (mut parts, body) = response.into_parts();
        let bytes = body.into_bytes().await.unwrap();

        let mut resp: graphql::Response = serde_json::from_slice(&bytes).unwrap();
        inigo.process_response(&mut resp);

        let bytes = serde_json::to_string(&resp).unwrap();
        parts.headers.remove("content-length");

        Ok(Response::from_parts(parts, Body::from(bytes)).into_response())
    }
}