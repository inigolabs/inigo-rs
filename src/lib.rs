#[macro_use]
extern crate lazy_static;

use std::{ptr, str};
use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::ops::ControlFlow;
use std::os::raw::c_char;
use std::process;
use std::ptr::null;
use std::sync::{Arc, Mutex};

use apollo_router::graphql;
use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::{Plugin, PluginInit};
use apollo_router::services::subgraph;
use apollo_router::services::supergraph::{BoxService, Request, Response};
use http::{HeaderMap, HeaderValue};
use libloading::{Library, Symbol};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
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
    output: &*mut c_char,
    output_len: &mut usize,
    status_output: &*mut c_char,
    status_output_len: &mut usize,
) -> usize {
    unsafe {
        type Func = extern "C" fn(
            handle_ptr: usize,
            header: *const c_char,
            header_len: usize,
            input: *const c_char,
            input_len: usize,
            output: &*mut c_char,
            output_len: &mut usize,
            status_output: &*mut c_char,
            status_output_len: &mut usize,
        ) -> usize;
        LIB.get::<Symbol<Func>>(b"process_request").unwrap()(
            handle_ptr,
            header,
            header_len,
            input,
            input_len,
            output,
            output_len,
            status_output,
            status_output_len,
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
) {
    unsafe {
        type Func = extern "C" fn(handle_ptr: usize, input: *const c_char);
        LIB.get::<Symbol<Func>>(b"update_schema").unwrap()(handle_ptr, input)
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
    jwt_header: String,
    handler: usize,
    processed: Arc<Mutex<usize>>,
}

impl Inigo {
    fn new(handler: usize, jwt_header: String) -> Self {
        return Inigo {
            handler,
            jwt_header,
            processed: Default::default(),
        };
    }

    fn get_jwt_header(headers: &HeaderMap<HeaderValue>, key: &str) -> (*const c_char, usize) {
        let header = headers.get(key);
        if header.is_none() {
            return (ptr::null(), 0);
        }

        let token = header.unwrap().to_str().unwrap();

        let jwt_header = serde_json::to_string(&JwtHeader { jwt: token }).unwrap();

        let jwt_header_len = jwt_header.len();

        return (CString::new(jwt_header).unwrap().into_raw(), jwt_header_len);
    }

    fn process_request(&self, req: &graphql::Request, headers: &HeaderMap<HeaderValue>) -> StatusResult {
        let (out, out_status, out_len, status_out_len) = (
            CString::into_raw(Default::default()),
            CString::into_raw(Default::default()),
            &mut 0,
            &mut 0,
        );

        let query = req.query.clone().unwrap();
        let query_len = query.len();

        let (header, header_len) = Inigo::get_jwt_header(headers, self.jwt_header.as_str());

        let mut processed = self.processed.lock().unwrap();
        *processed = process_request(
            self.handler,
            header,
            header_len,
            CString::into_raw(CString::new(query).unwrap()),
            query_len,
            &out,
            out_len,
            &out_status,
            status_out_len,
        );

        let res_out = unsafe { CStr::from_ptr(out).to_bytes()[..*out_len].to_owned() };
        dispose_memory(out);

        let res_out_status =
            unsafe { CStr::from_ptr(out_status).to_bytes()[..*status_out_len].to_owned() };
        dispose_memory(out_status);

        let mut result: StatusResult = StatusResult {
            status: Option::None,
            response: Option::None,
            request: Option::None,
        };

        if *out_len > 0 {
            result = serde_json::from_str(String::from_utf8(res_out).unwrap().as_str()).unwrap();
        }

        if *status_out_len > 0 {
            let status_result: StatusResult =
                serde_json::from_str(String::from_utf8(res_out_status.clone()).unwrap().as_str())
                    .unwrap();

            result.status = status_result.status;
            result.response = status_result.response;
        }

        return result;
    }

    fn process_response(&self, resp: &graphql::Response) -> graphql::Response {
        let v = serde_json::to_value(resp).unwrap();

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

        return result;
    }
}

#[derive(Debug)]
pub struct Middleware {
    jwt_header: String,
    handler: usize,
    enabled: bool,
    sidecars: HashMap<String, usize>,
}

impl Clone for Middleware {
    fn clone(&self) -> Middleware {
        Middleware {
            jwt_header: self.jwt_header.to_owned(),
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
    #[serde(default = "default_jwt_header")]
    jwt_header: String,
    #[serde(default)]
    service: String,
    token: String,
}

fn default_jwt_header() -> String {
    "authorization".to_string()
}

#[async_trait::async_trait]
impl Plugin for Middleware {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        if !init.config.enabled {
            return Ok(Middleware {
                jwt_header: String::new(),
                handler: 0,
                enabled: false,
                sidecars: Default::default(),
            });
        }

        let mut singleton = SINGLETON.lock().unwrap();
        if singleton.is_some() {
            let middleware = singleton.as_ref().unwrap().clone();
            update_schema(middleware.handler, str_to_c_char(init.supergraph_sdl.as_str()));
            return Ok(middleware);
        }

        let mut middleware = Middleware {
            jwt_header: init.config.jwt_header,
            handler: create(&SidecarConfig {
                debug: false,
                ingest: null(),
                service: str_to_c_char(&init.config.service),
                token: str_to_c_char(&init.config.token),
                schema: str_to_c_char(init.supergraph_sdl.as_str()),
                introspection: null(),
                egress_url: null(),
                gateway:null(),
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

        let inigo = Inigo::new(self.sidecars.get(_name).unwrap().clone(), self.jwt_header.to_owned());

        let process_req_fn = |i: Inigo| {
            move |mut req: subgraph::Request| {
                let result = i.process_request(req.subgraph_request.body(), req.subgraph_request.headers());

                if result.response.is_none() {
                    return Ok(ControlFlow::Continue(req));
                }

                let response = result.response.unwrap();

                // If request is blocked
                if result.status.unwrap() == "BLOCKED" {
                    dispose_handle(i.processed.lock().unwrap().clone());

                    return Ok(ControlFlow::Break(
                        subgraph::Response::builder()
                            .errors(response.errors)
                            .extensions(response.extensions)
                            .context(req.context)
                            .build(),
                    ));
                }

                // If request query has been mutated
                if response.errors.len() > 0 {
                    req.subgraph_request.body_mut().query = result.request.unwrap().query;
                }

                Ok(ControlFlow::Continue(req))
            }
        };

        let process_resp_fn = |i: Inigo| {
            move |mut resp: subgraph::Response| {
                let res = i.process_response(&resp.response.body());

                resp.response.body_mut().data = res.data;
                resp.response.body_mut().errors = res.errors;
                resp.response.body_mut().extensions = res.extensions;

                return resp;
            }
        };

        ServiceBuilder::new()
            .checkpoint(process_req_fn(inigo.clone()))
            .map_response(process_resp_fn(inigo.clone()))
            .service(service)
            .boxed()
    }

    fn supergraph_service(&self, service: BoxService) -> BoxService {
        if !self.enabled {
            return service;
        }

        let inigo = Inigo::new(self.handler.clone(), self.jwt_header.to_owned());

        let process_req_fn = |i: Inigo| {
            move |mut req: Request| {
                let result = i.process_request(&req.supergraph_request.body(), req.supergraph_request.headers());

                if result.response.is_none() {
                    return Ok(ControlFlow::Continue(req));
                }

                let response = result.response.unwrap();

                // is an introspection
                if !response.data.is_none()
                    && response
                    .data
                    .as_ref()
                    .unwrap()
                    .as_object()
                    .as_ref()
                    .unwrap()
                    .contains_key("__schema")
                {
                    dispose_handle(i.processed.lock().unwrap().clone());

                    return Ok(ControlFlow::Break(
                        Response::builder()
                            .data(response.data.unwrap())
                            .errors(response.errors)
                            .extensions(response.extensions)
                            .context(req.context)
                            .build()
                            .unwrap(),
                    ));
                }

                // If request is blocked
                if result.status.unwrap() == "BLOCKED" {
                    dispose_handle(i.processed.lock().unwrap().clone());

                    return Ok(ControlFlow::Break(
                        Response::builder()
                            .errors(response.errors)
                            .extensions(response.extensions)
                            .context(req.context)
                            .build()
                            .unwrap(),
                    ));
                }

                // If request query has been mutated
                if response.errors.len() > 0 {
                    req.supergraph_request.body_mut().query = result.request.unwrap().query;
                }

                Ok(ControlFlow::Continue(req))
            }
        };

        let process_resp_fn = |i: Inigo| {
            move |resp: Response| {
                return resp.map_stream(move |mut resp: graphql::Response| {
                    let res = i.process_response(&resp);

                    resp.data = res.data;
                    resp.errors = res.errors;
                    resp.extensions = res.extensions;

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

#[derive(Serialize)]
struct JwtHeader<'a> {
    jwt: &'a str,
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

#[derive(Deserialize, Clone)]
struct StatusResult {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    status: Option<String>,

    #[serde(flatten)]
    response: Option<graphql::Response>,
    #[serde(flatten)]
    request: Option<graphql::Request>,
}

fn str_to_c_char(val: &str) -> *const c_char {
    let res: *const c_char;
    if val.len() > 0 {
        res = CString::new(val.to_owned()).unwrap().into_raw();
    } else {
        res = ptr::null()
    }

    return res;
}
