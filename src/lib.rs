#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::ops::ControlFlow;
use std::os::raw::c_char;
use std::process;
use std::ptr::null;
use std::str;
use std::sync::{Arc, Mutex};

use apollo_router::graphql;
use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::{Plugin, PluginInit};
use apollo_router::services::{subgraph, supergraph};
use http::{HeaderMap, HeaderValue};
use libloading::{Library, Symbol};
use schemars::JsonSchema;
use serde::Deserialize;
use tower::{BoxError, ServiceBuilder, ServiceExt};
use tracing::error;

#[repr(C)]
struct SidecarConfig {
    debug: bool,
    ingest: *const c_char,
    service: *const c_char,
    token: *const c_char,
    schema: *const c_char,
    introspection: *const c_char,
    egress_url: *const c_char,
    gateway: *const usize,
}

const LIB_PATH: &str = "INIGO_LIB_PATH";

lazy_static! {
    static ref INIGO_LIB_PATH: String = match env::var_os(LIB_PATH) {
        Some(val) => val.into_string().unwrap(),
        None => {
            let ext = match sys_info::os_type().unwrap().as_str() {
                "Linux" => { "so" }
                "Darwin" => { "dylib" }
                "Windows" => { "dll" }
                _ => { "so" }
            };

            return env::current_exe().unwrap().parent().unwrap().join("libinigo.".to_owned() + ext).to_str().unwrap().to_owned();
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

                error!("{}", &msg);
                process::exit(1);
            }
        }
    };

      static ref SINGLETON: Mutex<Option<Middleware>> = Mutex::new(None);
}

fn create(ptr: *const SidecarConfig) -> usize {
    type Func = extern "C" fn(ptr: *const SidecarConfig) -> usize;

    unsafe { LIB.get::<Symbol<Func>>(b"create").unwrap()(ptr) }
}

fn dispose_memory(ptr: *mut c_char) {
    type Func = extern "C" fn(ptr: *mut c_char);
    unsafe {
        LIB.get::<Symbol<Func>>(b"disposeMemory").unwrap()(ptr);
    }
}

fn dispose_handle(handle: usize) {
    type Func = extern "C" fn(handle: usize);
    unsafe {
        LIB.get::<Symbol<Func>>(b"disposeHandle").unwrap()(handle);
    }
}

fn check_last_error() -> *const c_char {
    type Func = extern "C" fn() -> *const c_char;
    unsafe { LIB.get::<Symbol<Func>>(b"check_lasterror").unwrap()() }
}

fn process_request(
    handle_ptr: usize,
    header: *const c_char,
    header_len: usize,
    input: *const c_char,
    input_len: usize,
    resp: &*mut c_char,
    resp_len: &mut usize,
    req: &*mut c_char,
    req_len: &mut usize,
) -> usize {
    unsafe {
        type Func = extern "C" fn(
            handle_ptr: usize,
            header: *const c_char,
            header_len: usize,
            input: *const c_char,
            input_len: usize,
            resp: &*mut c_char,
            resp_len: &mut usize,
            req: &*mut c_char,
            req_len: &mut usize,
        ) -> usize;
        LIB.get::<Symbol<Func>>(b"process_request").unwrap()(
            handle_ptr,
            header,
            header_len,
            input,
            input_len,
            resp,
            resp_len,
            req,
            req_len,
        )
    }
}

fn process_response(
    handle_ptr: usize,
    req_handle: usize,
    input: *const c_char,
    input_len: usize,
    output: &*mut c_char,
    output_len: &mut usize,
) {
    unsafe {
        type Func = extern "C" fn(
            handle_ptr: usize,
            req_handle: usize,
            input: *const c_char,
            input_len: usize,
            output: &*mut c_char,
            output_len: &mut usize,
        );
        LIB.get::<Symbol<Func>>(b"process_response").unwrap()(
            handle_ptr, req_handle, input, input_len, output, output_len,
        )
    }
}

fn update_schema(
    handle_ptr: usize,
    input: *const c_char,
    input_len: usize,
) {
    unsafe {
        type Func = extern "C" fn(handle_ptr: usize, input: *const c_char, input_len: usize);
        LIB.get::<Symbol<Func>>(b"update_schema").unwrap()(handle_ptr, input, input_len)
    }
}

fn gateway_info(
    handle_ptr: usize,
    output: &*mut c_char,
    output_len: &mut usize,
) -> usize {
    unsafe {
        type Func = extern "C" fn(
            handle_ptr: usize,
            output: &*mut c_char,
            output_len: &mut usize,
        ) -> usize;
        LIB.get::<Symbol<Func>>(b"gateway_info").unwrap()(
            handle_ptr,
            output,
            output_len,
        )
    }
}

#[derive(Clone)]
struct Inigo {
    handler: usize,
    processed: Arc<Mutex<usize>>,
}

impl Inigo {
    fn new(handler: usize) -> Self {
        return Inigo {
            handler,
            processed: Default::default(),
        };
    }

    fn get_headers(headers: &HeaderMap<HeaderValue>) -> (*const c_char, usize) {
        let mut header_hashmap = HashMap::new();
        for (k, v) in headers {
            let k = k.as_str().to_owned();
            let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
            header_hashmap.entry(k).or_insert_with(Vec::new).push(v)
        }

        let h = serde_json::to_string(&header_hashmap).unwrap();

        let h_len = h.len();

        return (CString::new(h).unwrap().into_raw(), h_len);
    }

    fn process_request(&self, request: &mut graphql::Request, headers: &HeaderMap<HeaderValue>) -> Option<graphql::Response> {
        let (req, req_len, resp, resp_len) = (
            CString::into_raw(Default::default()),
            &mut 0,
            CString::into_raw(Default::default()),
            &mut 0,
        );

        let req_src: String = serde_json::to_string(&request).unwrap();

        let (header, header_len) = Inigo::get_headers(headers);

        let mut processed = self.processed.lock().unwrap();
        *processed = process_request(
            self.handler,
            header,
            header_len,
            CString::into_raw(CString::new(req_src.as_str()).unwrap()),
            req_src.len(),
            &resp,
            resp_len,
            &req,
            req_len,
        );

        let res_resp = unsafe { CStr::from_ptr(resp).to_bytes()[..*resp_len].to_owned() };
        dispose_memory(resp);

        let res_req =
            unsafe { CStr::from_ptr(req).to_bytes()[..*req_len].to_owned() };
        dispose_memory(req);

        if *resp_len > 0 {
            return serde_json::from_slice(res_resp.as_slice()).unwrap();
        }

        if *req_len > 0 {
            update_request(request, serde_json::from_slice(res_req.as_slice()).unwrap());
        }


        return None;
    }

    fn process_response(&self, resp: &mut graphql::Response) {
        let v = serde_json::to_value(&resp).unwrap();

        let _input = CString::into_raw(CString::new(v.to_string()).unwrap());
        let _input_len = v.to_string().len();

        let (out, out_len) = (CString::into_raw(Default::default()), &mut 0);

        process_response(
            self.handler,
            self.processed.lock().unwrap().clone(),
            _input,
            _input_len,
            &out,
            out_len,
        );

        let res_out = unsafe { CStr::from_ptr(out).to_bytes()[..*out_len].to_owned() };

        dispose_memory(out);

        dispose_handle(self.processed.lock().unwrap().clone());

        let result: graphql::Response =
            serde_json::from_str(String::from_utf8(res_out).unwrap().as_str()).unwrap();

        resp.data = result.data;
        resp.errors = result.errors;
        resp.extensions = result.extensions;
    }
}

#[derive(Debug)]
pub struct Middleware {
    handler: usize,
    enabled: bool,
    sidecars: HashMap<String, usize>,
}

impl Clone for Middleware {
    fn clone(&self) -> Middleware {
        Middleware {
            handler: self.handler,
            enabled: self.enabled,
            sidecars: self.sidecars.clone(),
        }
    }
}


fn default_as_true() -> bool {
    true
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct Conf {
    #[serde(default = "default_as_true")]
    enabled: bool,
    #[serde(default)]
    service: String,
    token: String,
}

#[async_trait::async_trait]
impl Plugin for Middleware {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        if !init.config.enabled {
            return Ok(Middleware {
                handler: 0,
                enabled: false,
                sidecars: Default::default(),
            });
        }

        let mut singleton = SINGLETON.lock().unwrap();
        if singleton.is_some() {
            let middleware = singleton.as_ref().unwrap().clone();
            update_schema(middleware.handler, str_to_c_char(init.supergraph_sdl.as_str()), init.supergraph_sdl.len());
            return Ok(middleware);
        }

        let mut middleware = Middleware {
            handler: create(&SidecarConfig {
                debug: false,
                ingest: null(),
                service: str_to_c_char(&init.config.service),
                token: str_to_c_char(&init.config.token),
                schema: str_to_c_char(init.supergraph_sdl.as_str()),
                introspection: null(),
                egress_url: null(),
                gateway: null(),
            }),
            enabled: true,
            sidecars: HashMap::new(),
        };

        let err = unsafe { CStr::from_ptr(check_last_error()) };

        if !err.to_str().unwrap().is_empty() {
            Err(err.to_str().unwrap())?;
        }

        let (out, out_len) = (CString::into_raw(Default::default()), &mut 0, );

        gateway_info(middleware.handler, &out, out_len);

        let res_out = unsafe { CStr::from_ptr(out).to_bytes()[..*out_len].to_owned() };

        dispose_memory(out);

        let mut result: Vec<GatewayInfo> = vec![];

        if *out_len > 0 {
            let info = String::from_utf8(res_out).unwrap().as_str().to_string();
            result = match serde_json::from_str(&info) {
                Ok(val) => val,
                Err(err) => {
                    let resp: graphql::Response = serde_json::from_str(&info).unwrap();

                    for error in resp.errors.iter() {
                        return Err(format!("{}", error))?;
                    }

                    return Err(BoxError::try_from(err).unwrap());
                }
            };
        }

        for info in result.iter() {
            middleware.sidecars.insert(info.name.to_owned(), create(&SidecarConfig {
                debug: false,
                egress_url: str_to_c_char(&info.url.as_str()),
                service: str_to_c_char(&init.config.service),
                token: str_to_c_char(&info.token.as_str()),
                schema: null(),
                introspection: null(),
                ingest: null(),
                gateway: middleware.handler as *const usize,
            }));

            let err = unsafe { CStr::from_ptr(check_last_error()) };

            if !err.to_str().unwrap().is_empty() {
                Err(err.to_str().unwrap())?;
            }
        }

        *singleton = Some(middleware.clone());

        Ok(middleware)
    }


    fn subgraph_service(&self, _name: &str, service: subgraph::BoxService) -> subgraph::BoxService {
        if !self.enabled {
            return service;
        }

        if !self.sidecars.contains_key(_name) {
            return service;
        }

        let inigo = Inigo::new(self.sidecars.get(_name).unwrap().clone());

        let process_req_fn = |i: Inigo| {
            move |mut req: subgraph::Request| {
                let headers = &req.subgraph_request.headers().clone();
                let resp = i.process_request(req.subgraph_request.body_mut(), headers);


                let traceparent = req.subgraph_request.body().extensions.get("traceparent");
                if traceparent.is_some() {
                    let traceparent_val = traceparent.unwrap().clone();
                    req.subgraph_request.headers_mut().append("traceparent", HeaderValue::from_str(traceparent_val.as_str().unwrap()).unwrap());
                }


                if resp.is_none() {
                    return Ok(ControlFlow::Continue(req));
                }

                let response = resp.unwrap();

                dispose_handle(i.processed.lock().unwrap().clone());

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

        let inigo = Inigo::new(self.handler.clone());

        let process_req_fn = |i: Inigo| {
            move |mut req: supergraph::Request| {
                let headers = &req.supergraph_request.headers().clone();
                let resp = i.process_request(req.supergraph_request.body_mut(), headers);

                let traceparent = req.supergraph_request.body().extensions.get("traceparent");
                if traceparent.is_some() {
                    let traceparent_val = traceparent.unwrap().clone();
                    req.supergraph_request.headers_mut().append("traceparent",HeaderValue::from_str( traceparent_val.as_str().unwrap()).unwrap());
                }

                if resp.is_none() {
                    return Ok(ControlFlow::Continue(req));
                }

                let response = resp.unwrap();

                dispose_handle(i.processed.lock().unwrap().clone());

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
            .map_response(process_resp_fn(inigo.clone()))
            .service(service)
            .boxed()
    }
}

fn update_request(req: &mut graphql::Request, result: graphql::Request) {
    req.operation_name = result.operation_name;
    req.query = result.query;
    req.variables = result.variables;
    req.extensions = result.extensions;
}

#[derive(Deserialize, Clone)]
struct GatewayInfo {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    token: String,
}

fn str_to_c_char(val: &str) -> *const c_char {
    if val.len() > 0 {
        return CString::new(val.to_owned()).unwrap().into_raw();
    }

    return null();
}
