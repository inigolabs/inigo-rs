pub mod registry;

#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::ops::ControlFlow;
use std::os::raw::c_char;
use std::process;
use std::ptr::{null, null_mut};
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

#[repr(C)]
pub struct SidecarConfig {
    pub debug: bool,
    pub ingest: *const c_char,
    pub service: *const c_char,
    pub token: *const c_char,
    pub schema: *const c_char,
    pub introspection: *const c_char,
    pub egress_url: *const c_char,
    pub gateway: *const usize,
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
        unsafe { LIB.get(b"process_request").unwrap() };
    static ref CREATE: Symbol<'static, FnCreate> = unsafe { LIB.get(b"create").unwrap() };
    static ref DISPOSE_HANDLE: Symbol<'static, FnDisposeHandle> =
        unsafe { LIB.get(b"disposeHandle").unwrap() };
    static ref CHECK_LAST_ERROR: Symbol<'static, FnCheckLastError> =
        unsafe { LIB.get(b"check_lasterror").unwrap() };
    static ref PROCESS_RESPONSE: Symbol<'static, FnProcessResponse> =
        unsafe { LIB.get(b"process_response").unwrap() };
    static ref UPDATE_SCHEMA: Symbol<'static, FnUpdateSchema> =
        unsafe { LIB.get(b"update_schema").unwrap() };
    static ref GATEWAY_INFO: Symbol<'static, FnGatewayInfo> =
        unsafe { LIB.get(b"gateway_info").unwrap() };
}

type FnGatewayInfo =
    extern "C" fn(handle_ptr: usize, output: &*mut c_char, output_len: &mut usize) -> usize;

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

type FnCreate = extern "C" fn(ptr: *const SidecarConfig) -> usize;

type FnProcessRequest = extern "C" fn(
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

    fn get_headers(headers: &HeaderMap<HeaderValue>) -> (CString, usize) {
        let mut header_hashmap = HashMap::new();
        for (k, v) in headers {
            let k = k.as_str().to_owned();
            let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
            header_hashmap.entry(k).or_insert_with(Vec::new).push(v)
        }

        let h = serde_json::to_string(&header_hashmap).unwrap();

        let h_len = h.len();

        return (CString::new(h).expect("CString::new failed"), h_len);
    }

    pub fn process_request(
        &self,
        request: &mut graphql::Request,
        headers: &HeaderMap<HeaderValue>,
    ) -> Option<graphql::Response> {
        let (req, req_len, resp, resp_len) = (null_mut(), &mut 0, null_mut(), &mut 0);

        let req_src: String = serde_json::to_string(&request).unwrap();

        let req_src_len = req_src.len();
        let req_src_cstr = CString::new(req_src).expect("CString::new failed");

        let (header, header_len) = Inigo::get_headers(headers);

        let mut processed = self.processed.lock().unwrap();
        *processed = PROCESS_REQUEST(
            self.handler,
            header.as_ptr(),
            header_len,
            req_src_cstr.as_ptr(),
            req_src_len,
            &resp,
            resp_len,
            &req,
            req_len,
        );

        if !resp.is_null() {
            let res_resp = unsafe { CString::from_raw(resp).to_bytes()[..*resp_len].to_owned() };
            DISPOSE_HANDLE(*processed);
            return serde_json::from_slice(&res_resp).unwrap();
        }

        if !req.is_null() {
            let res_req = unsafe { CString::from_raw(req).to_bytes()[..*req_len].to_owned() };
            update_request(request, serde_json::from_slice(&res_req).unwrap());
        }

        return None;
    }

    pub fn process_response(&self, resp: &mut graphql::Response) {
        let v = serde_json::to_value(&resp).unwrap().to_string();

        let input_len = v.len();
        let input = CString::new(v).expect("CString::new failed");

        let (out, out_len) = (null_mut(), &mut 0);

        let processed = self.processed.lock().unwrap().clone();

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

        let res_out = unsafe { CString::from_raw(out).to_bytes()[..*out_len].to_owned() };

        DISPOSE_HANDLE(processed);

        let result: graphql::Response = serde_json::from_slice(&res_out).unwrap();

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
            let sdl = CString::new(init.supergraph_sdl.as_str())
                .unwrap()
                .into_raw();

            UPDATE_SCHEMA(middleware.handler, sdl, init.supergraph_sdl.len());

            // Take the ownership back to rust and drop the owner
            let _ = unsafe { CString::from_raw(sdl) };

            return Ok(middleware);
        }

        let mut middleware = Middleware {
            handler: CREATE(&SidecarConfig {
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

        let err = unsafe { CString::from_raw(CHECK_LAST_ERROR()) };

        if !err.to_str().unwrap().is_empty() {
            Err(err.to_str().unwrap())?;
        }

        let (out, out_len) = (null_mut(), &mut 0);

        GATEWAY_INFO(middleware.handler, &out, out_len);

        if out.is_null() {
            println!("gateway info response cannot be null");
            process::exit(1);
        }

        let res_out = unsafe { CString::from_raw(out).to_bytes()[..*out_len].to_owned() };

        let mut result: Vec<GatewayInfo> = vec![];

        if *out_len > 0 {
            result = match serde_json::from_slice(&res_out) {
                Ok(val) => val,
                Err(err) => {
                    let resp: graphql::Response = serde_json::from_slice(&res_out).unwrap();

                    for error in resp.errors.iter() {
                        return Err(format!("{}", error))?;
                    }

                    return Err(BoxError::try_from(err).unwrap());
                }
            };
        }

        for info in result.iter() {
            middleware.sidecars.insert(
                info.name.to_owned(),
                CREATE(&SidecarConfig {
                    debug: false,
                    egress_url: null(),
                    service: str_to_c_char(&init.config.service),
                    token: str_to_c_char(&info.token.as_str()),
                    schema: null(),
                    introspection: null(),
                    ingest: null(),
                    gateway: middleware.handler as *const usize,
                }),
            );

            let err = unsafe { CString::from_raw(CHECK_LAST_ERROR()) };

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
                    req.subgraph_request.headers_mut().append(
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

        let inigo = Inigo::new(self.handler.clone());

        let process_req_fn = |i: Inigo| {
            move |mut req: supergraph::Request| {
                let headers = &req.supergraph_request.headers().clone();
                let resp = i.process_request(req.supergraph_request.body_mut(), headers);

                let traceparent = req.supergraph_request.body().extensions.get("traceparent");
                if traceparent.is_some() {
                    let traceparent_val = traceparent.unwrap().clone();
                    req.supergraph_request.headers_mut().append(
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
    token: String,
}

fn str_to_c_char(val: &str) -> *const c_char {
    if val.len() > 0 {
        return CString::new(val.to_owned()).unwrap().into_raw();
    }

    return null();
}
