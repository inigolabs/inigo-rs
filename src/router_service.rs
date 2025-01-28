use apollo_router::layers::ServiceBuilderExt;
use apollo_router::services::router;
use futures::future::BoxFuture;
use std::task::Context;
use std::task::Poll;
use tower::buffer::Buffer;
use tower::{BoxError, Service, ServiceBuilder};

#[derive(Clone)]
pub(crate) struct RouterService {
    service: Buffer<router::BoxService, router::Request>,
}

impl RouterService {
    #[allow(dead_code)]
    pub(crate) fn new(service: router::BoxService) -> Self {
        Self {
            service: ServiceBuilder::new().buffered().service(service),
        }
    }
}

impl Service<router::Request> for RouterService {
    type Response = router::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: router::Request) -> Self::Future {
        let clone = self.service.clone();
        let mut inner = std::mem::replace(&mut self.service, clone);

        let fut = async move {
            let mut res = inner.call(req).await?;
            let (parts, res_body) = res.response.into_parts();
            let original_res_body = hyper::body::to_bytes(res_body).await?;
            res.response = http::Response::from_parts(parts, hyper::Body::from(original_res_body));
            Ok(res)
        };

        Box::pin(fut)
    }
}