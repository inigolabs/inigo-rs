use tower::{BoxError, Service};
use apollo_router::services::router;
use futures::future::BoxFuture;

pub struct ProxyService {
    pub url: hyper::Uri,
}

impl Service<router::Request> for ProxyService {
    type Response = router::Response;

    type Error = BoxError;

    type Future = BoxFuture<'static, router::ServiceResult>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: router::Request) -> Self::Future {
        let scheme = self.url.scheme().unwrap().clone();
        let authority = self.url.authority().unwrap().clone();

        let fut = async move {
            let client = hyper::Client::new();

            let uri = req.router_request.uri();
            let new_uri = http::Uri::builder()
                .scheme(scheme.as_str())
                .authority(authority.as_str())
                .path_and_query(uri.path_and_query().unwrap().clone().as_str())
                .build()
                .unwrap();

            *req.router_request.uri_mut() = new_uri;

            let resp = client.request(req.router_request).await.unwrap();

            Ok(router::Response::from(resp))
        };

        Box::pin(fut)
    }
}
