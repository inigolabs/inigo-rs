pub mod axum;
pub mod registry;

#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::os::raw::c_char;
use std::process;
use std::ptr::{null, null_mut};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use apollo_router::graphql;
use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::{Plugin, PluginInit};
use apollo_router::services::router;
use apollo_router::services::{subgraph, supergraph};
use apollo_router::Endpoint;
use apollo_router::ListenAddr;
use futures::future::BoxFuture;
use http::{HeaderMap, HeaderName, HeaderValue};
use libloading::{Library, Symbol};
use multimap::MultiMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json_bytes::{ByteString, Value};
use std::task::Context;
use std::task::Poll;
use tower::buffer::Buffer;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

#[repr(C)]
pub struct SidecarConfig {
    pub debug: bool,
    pub name: *const c_char,
    pub service: *const c_char,
    pub token: *const c_char,
    pub schema: *const c_char,
    pub runtime: *const c_char,
    pub egress_url: *const c_char,
    pub gateway: *const usize,
    pub disable_response_data: bool,
}

const LIB_PATH: &str = "INIGO_LIB_PATH";

lazy_static! {
    static ref INIGO_LIB_PATH: String = match env::var_os(LIB_PATH) {
        Some(val) => val.into_string().unwrap(),
        None => {
            let ext = match sys_info::os_type().unwrap().as_str() {
                "Linux" => "so",
                "Darwin" => "dylib",
                "Windows" => "dll",
                _ => "so",
            };

            return env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .join("libinigo.".to_owned() + ext)
                .to_str()
                .unwrap()
                .to_owned();
        }
    };
    static ref LIB: Library = unsafe {
        return match Library::new(format!("{}", INIGO_LIB_PATH.as_str())) {
            Ok(val) => val,
            Err(e) => {
                let mut msg: String = e.to_string();
                if msg.contains("No such file or directory") {
                    msg = format!("The router could not find the Inigo library, please make sure you specified {}=/path/to/libinigo.so", LIB_PATH);
                };

                println!("{}", &msg);
                process::exit(1);
            }
        };
    };
    static ref SINGLETON: Mutex<Option<Middleware>> = Mutex::new(None);
    static ref PROCESS_REQUEST: Symbol<'static, FnProcessRequest> =
        unsafe { LIB.get(b"process_service_request").unwrap() };
    static ref CREATE: Symbol<'static, FnCreate> = unsafe { LIB.get(b"create").unwrap() };
    pub static ref CREATE_MOCK: Symbol<'static, FnCreate> =
        unsafe { LIB.get(b"create_mock").unwrap() };
    static ref DISPOSE_HANDLE: Symbol<'static, FnDisposeHandle> =
        unsafe { LIB.get(b"disposeHandle").unwrap() };
    static ref DISPOSE_MEMORY: Symbol<'static, FnDisposeMemory> =
        unsafe { LIB.get(b"disposeMemory").unwrap() };
    static ref CHECK_LAST_ERROR: Symbol<'static, FnCheckLastError> =
        unsafe { LIB.get(b"check_lasterror").unwrap() };
    static ref PROCESS_RESPONSE: Symbol<'static, FnProcessResponse> =
        unsafe { LIB.get(b"process_response").unwrap() };
    static ref UPDATE_SCHEMA: Symbol<'static, FnUpdateSchema> =
        unsafe { LIB.get(b"update_schema").unwrap() };
}

type FnUpdateSchema = extern "C" fn(handle_ptr: usize, input: *mut c_char, input_len: usize);

type FnProcessResponse = extern "C" fn(
    handle_ptr: usize,
    req_handle: usize,
    input: *const c_char,
    input_len: usize,
    output: &*mut c_char,
    output_len: &mut usize,
);

type FnCheckLastError = extern "C" fn() -> *mut c_char;

type FnDisposeHandle = extern "C" fn(handle: usize);

type FnDisposeMemory = extern "C" fn(ptr: *mut c_char);

type FnCreate = extern "C" fn(ptr: *const SidecarConfig) -> usize;

type FnProcessRequest = extern "C" fn(
    handle_ptr: usize,
    subgraph_name: *const c_char,
    subgraph_name_len: usize,
    header: *const c_char,
    header_len: usize,
    input: *const c_char,
    input_len: usize,
    resp: &*mut c_char,
    resp_len: &mut usize,
    req: &*mut c_char,
    req_len: &mut usize,
) -> usize;

#[derive(Clone)]
pub struct Inigo {
    handler: usize,
    processed: Arc<Mutex<usize>>,
}

impl Inigo {
    pub fn new(handler: usize) -> Self {
        return Inigo {
            handler,
            processed: Default::default(),
        };
    }

    fn get_headers(headers: &HeaderMap<HeaderValue>) -> String {
        let mut header_hashmap = HashMap::new();
        for (k, v) in headers {
            let k = k.as_str().to_owned();
            let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
            header_hashmap.entry(k).or_insert_with(Vec::new).push(v)
        }

        return serde_json::to_string(&header_hashmap).unwrap();
    }

    pub fn process_request(
        &self,
        name: &str,
        request: &mut graphql::Request,
        headers: &HeaderMap<HeaderValue>,
    ) -> Option<graphql::Response> {
        let (req, req_len, resp, resp_len) = (null_mut(), &mut 0, null_mut(), &mut 0);

        let req_src: String = serde_json::to_string(&request).unwrap();

        let req_src_len = req_src.len();
        let req_src_cstr = CString::new(req_src).expect("CString::new failed");

        let h = Inigo::get_headers(headers);

        let header_len = h.len();
        let header_cstr = CString::new(h).expect("CString::new failed");

        let name_len = name.len();
        let name_cstr = CString::new(name).expect("CString::new failed");

        let mut processed = self.processed.lock().unwrap();
        *processed = PROCESS_REQUEST(
            self.handler,
            name_cstr.as_ptr(),
            name_len,
            header_cstr.as_ptr(),
            header_len,
            req_src_cstr.as_ptr(),
            req_src_len,
            &resp,
            resp_len,
            &req,
            req_len,
        );

        if !resp.is_null() {
            let res_resp = from_raw(resp, *resp_len).to_owned();
            DISPOSE_HANDLE(*processed);
            DISPOSE_MEMORY(resp);
            return serde_json::from_slice(&res_resp).unwrap();
        }

        if !req.is_null() {
            let res_req = from_raw(req, *req_len).to_owned();
            DISPOSE_MEMORY(req);
            update_request(request, serde_json::from_slice(&res_req).unwrap());
        }

        return None;
    }

    pub fn process_response(&self, resp: &mut graphql::Response) {
        let processed = self.processed.lock().unwrap().clone();
        if processed == 0 {
            return;
        }

        let v = serde_json::to_value(&ResponseWrapper {
            errors: resp.errors.clone(),
            response_size: 0,
            response_body_counts: count_response_fields(resp),
        })
        .unwrap()
        .to_string();

        let input_len = v.len();
        let input = CString::new(v).expect("CString::new failed");

        let (out, out_len) = (null_mut(), &mut 0);

        PROCESS_RESPONSE(
            self.handler,
            processed,
            input.as_ptr(),
            input_len,
            &out,
            out_len,
        );

        if out.is_null() {
            return;
        }

        let res_out = from_raw(out, *out_len).to_owned();

        DISPOSE_HANDLE(processed);
        DISPOSE_MEMORY(out);

        let result: graphql::Response = serde_json::from_slice(&res_out).unwrap();

        for err in result.errors {
            resp.errors.push(err)
        }

        for (field_name, field_value) in result.extensions {
            resp.extensions.insert(field_name, field_value);
        }
    }
}

fn from_raw(ptr: *mut c_char, len: usize) -> &'static [u8] {
    return unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        &*(slice as *mut [c_char] as *mut [u8])
    };
}

fn count_response_fields(resp: &graphql::Response) -> HashMap<ByteString, usize> {
    let mut counts = HashMap::new();
    if resp.data.is_some() {
        count_response_fields_recursive(&mut counts, &"data".into(), resp.data.as_ref().unwrap());
    }

    let data: ByteString = "data".into();
    if !counts.contains_key(&data) {
        counts.insert(data, 1);
    }
    counts.insert("errors".into(), resp.errors.len());
    counts
}

fn count_response_fields_recursive(
    hm: &mut HashMap<ByteString, usize>,
    prefix: &ByteString,
    val: &Value,
) -> bool {
    let mut is_arr: bool = false;
    match &val {
        Value::Object(obj) => {
            for (k, v) in obj {
                let key: ByteString =
                    (prefix.as_str().to_owned() + "." + k.clone().as_str()).into();
                if count_response_fields_recursive(hm, &key, v) {
                    continue;
                }

                let mut current: usize = 0;
                if hm.contains_key(&key) {
                    current = *hm.get(&key).unwrap();
                }
                hm.insert(key.clone(), current + 1);
            }
        }
        Value::Array(arr) => {
            is_arr = true;
            for v in arr {
                if count_response_fields_recursive(hm, prefix, v) {
                    continue;
                }

                let mut current: usize = 0;
                if hm.contains_key(prefix) {
                    current = *hm.get(prefix).unwrap();
                }
                hm.insert(prefix.clone(), current + 1);
            }
        }
        _ => {}
    }

    return is_arr;
}

#[derive(Serialize, Deserialize)]
struct ResponseWrapper {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    errors: Vec<graphql::Error>,
    response_size: usize,
    response_body_counts: HashMap<ByteString, usize>,
}

#[derive(Debug)]
pub struct Middleware {
    handler: usize,
    enabled: bool,
    subgraphs_analytics: bool,
    trace_header: String,
}

impl Clone for Middleware {
    fn clone(&self) -> Middleware {
        Middleware {
            handler: self.handler,
            enabled: self.enabled,
            subgraphs_analytics: self.subgraphs_analytics,
            trace_header: self.trace_header.clone(),
        }
    }
}

fn default_as_true() -> bool {
    true
}

fn default_trace_header() -> String {
    "Inigo-Router-TraceID".to_string()
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct Conf {
    #[serde(default = "default_as_true")]
    enabled: bool,
    #[serde(default)]
    service: String,
    token: String,
    #[serde(default = "default_as_true")]
    subgraphs_analytics: bool,
    #[serde(default = "default_trace_header")]
    trace_header: String,
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
            });
        }

        let mut singleton = SINGLETON.lock().unwrap();
        if singleton.is_some() {
            let middleware = singleton.as_ref().unwrap().clone();
            let sdl = CString::new(init.supergraph_sdl.as_str())
                .unwrap()
                .into_raw();

            UPDATE_SCHEMA(middleware.handler, sdl, init.supergraph_sdl.len());

            // Take the ownership back to rust and drop the owner
            let _ = unsafe { CString::from_raw(sdl) };

            return Ok(middleware);
        }

        let middleware = Middleware {
            handler: CREATE(&SidecarConfig {
                debug: false,
                service: str_to_c_char(&init.config.service),
                token: str_to_c_char(&init.config.token),
                schema: str_to_c_char(init.supergraph_sdl.as_str()),
                name: str_to_c_char("inigo-rs"),
                runtime: null(),
                egress_url: null(),
                gateway: null(),
                disable_response_data: true,
            }),
            enabled: init.config.enabled,
            subgraphs_analytics: init.config.subgraphs_analytics,
            trace_header: init.config.trace_header,
        };

        let err = unsafe { std::ffi::CStr::from_ptr(CHECK_LAST_ERROR()) };

        if !err.to_str().unwrap().is_empty() {
            Err(err.to_str().unwrap())?;
        }

        *singleton = Some(middleware.clone());

        Ok(middleware)
    }

    // NOTE: Uncomment it to enable RouterService
    // fn router_service(&self, service: router::BoxService) -> router::BoxService {
    //     RouterService::new(service).boxed()
    // }

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
                        .build(),
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

        let trace = self.trace_header.clone();

        let inigo = Inigo::new(self.handler.clone());

        let process_req_fn = |i: Inigo| {
            move |mut req: supergraph::Request| {
                req.supergraph_request
                    .headers_mut()
                    .entry(HeaderName::from_str(&trace).unwrap())
                    .or_insert(HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap());

                let headers = &req.supergraph_request.headers().clone();
                let resp = i.process_request("", req.supergraph_request.body_mut(), headers);

                let traceparent = req.supergraph_request.body().extensions.get("traceparent");
                if traceparent.is_some() {
                    let traceparent_val = traceparent.unwrap().clone();
                    req.supergraph_request.headers_mut().insert(
                        "traceparent",
                        HeaderValue::from_str(traceparent_val.as_str().unwrap()).unwrap(),
                    );
                }

                if resp.is_none() {
                    return Ok(ControlFlow::Continue(req));
                }

                let response = resp.unwrap();

                return Ok(ControlFlow::Break(
                    supergraph::Response::builder()
                        .data(response.data.unwrap_or_default())
                        .errors(response.errors)
                        .extensions(response.extensions)
                        .context(req.context)
                        .build()
                        .unwrap(),
                ));
            }
        };

        let process_resp_fn = |i: Inigo| {
            move |resp: supergraph::Response| {
                return resp.map_stream(move |mut resp: graphql::Response| {
                    i.process_response(&mut resp);
                    return resp;
                });
            }
        };

        ServiceBuilder::new()
            .checkpoint(process_req_fn(inigo.clone()))
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
            ProxyService {
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

struct ProxyService {
    url: hyper::Uri,
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

fn update_request(req: &mut graphql::Request, result: graphql::Request) {
    req.operation_name = result.operation_name;
    req.query = result.query;
    req.variables = result.variables;
    req.extensions = result.extensions;
}

fn str_to_c_char(val: &str) -> *const c_char {
    if val.len() > 0 {
        return CString::new(val.to_owned()).unwrap().into_raw();
    }

    return null();
}

#[cfg(test)]
mod tests {
    use super::*;
    use apollo_router::graphql;
    use rstest::*;

    #[rstest]
    #[case(
        r#"{"data":{"key1":"val1","key2":"val2"}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.key1".into(), 1),
            ("data.key2".into(), 1),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":{"key":[]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":{"key1":[["val1.0","val1.1","val1.2"],["val1.0","val1.1",["v1","v2"]]],"key2":["val2.0","val2.1"]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.key1".into(), 7),
            ("data.key2".into(), 2),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":{"key1":["val1.0","val1.1"],"key2":["val2.0","val2.1"]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.key1".into(), 2),
            ("data.key2".into(), 2),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":[{"key":"val"},{"key":"val"}]}"#,
        HashMap::from([
            ("data".into(), 2),
            ("data.key".into(), 2),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":null}"#,
        HashMap::from([
            ("data".into(), 1),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":{"first":[{"key":"val"},{"key":"val"}],"second":[{"key":"val"},{"key":"val"}]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.first".into(), 2),
            ("data.first.key".into(), 2),
            ("data.second".into(), 2),
            ("data.second.key".into(), 2),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":{"first":[{"key1":"val"},{"key2":"val"}],"second":[{"key1":"val"},{"key2":"val"}]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.first".into(), 2),
            ("data.first.key1".into(), 1),
            ("data.first.key2".into(), 1),
            ("data.second".into(), 2),
            ("data.second.key1".into(), 1),
            ("data.second.key2".into(), 1),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":{"first":[{"key":"val","key1":"val"},{"key":"val","key2":"val"}],"second":[{"key":"val","key1":"val"},{"key":"val","key2":"val"}]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.first".into(), 2),
            ("data.first.key".into(), 2),
            ("data.first.key1".into(), 1),
            ("data.first.key2".into(), 1),
            ("data.second".into(), 2),
            ("data.second.key".into(), 2),
            ("data.second.key1".into(), 1),
            ("data.second.key2".into(), 1),
            ("errors".into(), 0),
        ]),
    )]
    #[case(
        r#"{"data":{"first":[{"key":"val","key1":{"first":[{"key":"val","key1":"val"},{"key":"val","key2":"val"}]}},["ignore",{"nested":"val"}],{"key":"val","key2":"val"}],"second":[{"key":[{"first":[{"key":"val","key1":"val"},{"key":"val","key2":"val"}]}],"key1":"val"},{"key":"val","key2":"val"}]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.first".into(), 4),
            ("data.first.key".into(), 2),
            ("data.first.key1".into(), 1),
            ("data.first.key1.first".into(), 2),
            ("data.first.key1.first.key".into(), 2),
            ("data.first.key1.first.key1".into(), 1),
            ("data.first.key1.first.key2".into(), 1),
            ("data.first.key2".into(), 1),
            ("data.first.nested".into(), 1),
            ("data.second".into(), 2),
            ("data.second.key".into(), 2),
            ("data.second.key.first".into(), 2),
            ("data.second.key.first.key".into(), 2),
            ("data.second.key.first.key1".into(), 1),
            ("data.second.key.first.key2".into(), 1),
            ("data.second.key1".into(), 1),
            ("data.second.key2".into(), 1),
            ("errors".into(), 0),
        ]),
    )]

    fn count_response(#[case] raw: &str, #[case] expected: HashMap<ByteString, usize>) {
        let result: graphql::Response = serde_json::from_str(raw).unwrap();
        assert_eq!(count_response_fields(&result), expected);
    }
}
