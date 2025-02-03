use std::env;
use std::process;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};
use std::ptr::{null, null_mut};
use std::collections::{HashSet, HashMap};

use log::{error, info, debug};
use apollo_router::graphql;
use libloading::{Library, Symbol};
use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json_bytes::ByteString;

use crate::parser::response_counts;

const LIB_PATH: &str = "INIGO_LIB_PATH";

#[derive(Clone)]
pub struct Inigo {
    pub instance: usize,
    pub handle: Arc<Mutex<usize>>,
    pub scalars: Arc<Mutex<HashSet<String>>>,
}

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

#[derive(Serialize, Deserialize)]
struct ResponseWrapper {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    errors: Vec<graphql::Error>,
    response_size: usize,
    response_body_counts: HashMap<ByteString, usize>,
}

type FnCreate           = extern "C" fn(ptr: *const SidecarConfig) -> usize;
type FnUpdateSchema     = extern "C" fn(handle_ptr: usize, input: *mut c_char, input_len: usize);
type FnCheckLastError   = extern "C" fn() -> *mut c_char;
type FnDisposeHandle    = extern "C" fn(handle: usize);
type FnDisposePinner    = extern "C" fn(handle: usize);
type FnProcessRequest   = extern "C" fn(
    handle_ptr: usize,
    subgraph_name: *const c_char,
    subgraph_name_len: usize,
    header: *const c_char,
    header_len: usize,
    input: *const c_char,
    input_len: usize,
    resp: &*mut u8,
    resp_len: &mut usize,
    req: &*mut u8,
    req_len: &mut usize,
    analysis: &*mut u8,
    analysis_len: &mut usize,
) -> usize;

type FnProcessResponse  = extern "C" fn(
    handle_ptr: usize,
    req_handle: usize,
    input: *const c_char,
    input_len: usize,
    output: &*mut u8,
    output_len: &mut usize,
);

mod lib {
    use super::*;
    lazy_static! {
        pub(super) static ref INIGO_LIB_PATH: String = match env::var_os(LIB_PATH) {
            Some(val) => val.into_string().unwrap(),
            None => {
                return env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("libinigo.".to_owned() + get_file_extension())
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

                    error!("{}", &msg);
                    process::exit(1);
                }
            };
        };
        
        pub static ref CREATE_MOCK:      Symbol<'static, FnCreate> =            unsafe { LIB.get(b"create_mock").unwrap() };
        pub static ref CREATE:           Symbol<'static, FnCreate> =            unsafe { LIB.get(b"create").unwrap() };
        pub static ref CHECK_LAST_ERROR: Symbol<'static, FnCheckLastError> =    unsafe { LIB.get(b"check_lasterror").unwrap() };
        pub static ref UPDATE_SCHEMA:    Symbol<'static, FnUpdateSchema> =      unsafe { LIB.get(b"update_schema").unwrap() };
        pub static ref DISPOSE_HANDLE:   Symbol<'static, FnDisposeHandle> =     unsafe { LIB.get(b"disposeHandle").unwrap() };
        pub static ref DISPOSE_PINNER:   Symbol<'static, FnDisposePinner> =     unsafe { LIB.get(b"disposePinner").unwrap() };
        pub static ref PROCESS_REQUEST:  Symbol<'static, FnProcessRequest> =    unsafe { LIB.get(b"process_service_request_v2").unwrap() };
        pub static ref PROCESS_RESPONSE: Symbol<'static, FnProcessResponse> =   unsafe { LIB.get(b"process_response").unwrap() };
    }
}

pub fn create(config: &SidecarConfig) -> Result<usize, String> {
    let handle = lib::CREATE(config);

    let err = unsafe { std::ffi::CStr::from_ptr(lib::CHECK_LAST_ERROR()) };
    if !err.to_str().unwrap().is_empty() {
       return Err(err.to_str().unwrap().to_owned());
    }

    return Ok(handle);
}

pub fn create_mock(config: &SidecarConfig) -> usize {
    return lib::CREATE_MOCK(config);
}

pub fn update_schema(handler: usize, schema: &str) {
    let schema_len = schema.len();
    let schema_cstr = CString::new(schema).unwrap().into_raw();
    lib::UPDATE_SCHEMA(handler, schema_cstr, schema_len);
    unsafe { let _ = CString::from_raw(schema_cstr); };
}

impl Inigo {
    pub fn new(instance: usize) -> Self {
        return Inigo {
            instance,
            handle: Default::default(),
            scalars: Default::default(),
        };
    }

    pub fn process_request(&self, name: &str, request: &mut graphql::Request, headers: &HeaderMap<HeaderValue>) -> Option<graphql::Response> {
        let req_str: String = serde_json::to_string(&request).unwrap();

        let mut req_mut_data: Option<Vec<u8>> = None;
        let mut scalars_data: Option<HashSet<String>> = None;
        let mut resp_data: Option<Vec<u8>> = None;

        let handle = process_request(
            self.instance,
            Some(name),
            req_str.as_bytes(),
            headers,
            &mut req_mut_data,
            &mut scalars_data,
            &mut resp_data
        );

        self.set_handle(handle);

        // Only set scalars if present
        if scalars_data.is_some() {
            self.set_scalars(scalars_data.unwrap());
        }

        if resp_data.is_some() {
            return serde_json::from_slice(resp_data.unwrap().as_slice()).unwrap();
        }

        // Only deserialize mutated request if present
        if req_mut_data.is_some() {
            let result: graphql::Request = serde_json::from_slice(&req_mut_data.unwrap()).unwrap();
            request.operation_name = result.operation_name;
            request.query = result.query;
            request.variables = result.variables;
            request.extensions = result.extensions;
        }

        return None;
    }

    pub fn process_response(&self, resp: &mut graphql::Response) {
        let handle = self.handle.lock().unwrap().clone();
        if handle == 0 {
            return;
        }

        let v: String = serde_json::to_value(&ResponseWrapper {
            errors: resp.errors.clone(),
            response_size: 0,
            response_body_counts: response_counts(resp, self.scalars.lock().unwrap().clone()),
        }).unwrap().to_string();

        let input_len = v.len();
        let input = CString::new(v).unwrap();

        let out: *mut u8 = null_mut();
        let out_len: &mut usize = &mut 0;

        let _ = lib::PROCESS_RESPONSE(
            self.instance,
            handle,
            input.as_ptr(),
            input_len,
            &out,
            out_len,
        );

        debug!("inigo-rs: response, {:?}, {}", out, out_len);

        if out.is_null() {
            dispose_handle(handle);
            return;
        }

        let res_out = unsafe { std::slice::from_raw_parts_mut(out, *out_len) };
        let result: graphql::Response = serde_json::from_slice(&res_out).unwrap();

        for err in result.errors {
            resp.errors.push(err)
        }

        for (field_name, field_value) in result.extensions {
            resp.extensions.insert(field_name, field_value);
        }

        dispose_handle(handle);
    }

    pub(crate) fn set_handle(&self, val: usize) {
        let mut processed = self.handle.lock().unwrap();
        *processed = val;
    }

    pub(crate) fn set_scalars(&self, val: HashSet<String>) {
        let mut scalars = self.scalars.lock().unwrap();
        *scalars = val;
    }
}

pub(crate) fn process_request(
    handler: usize,
    name: Option<&str>,
    req_src: &[u8],
    headers: &HeaderMap<HeaderValue>,
    out_req: &mut Option<Vec<u8>>,
    out_scalars: &mut Option<HashSet<String>>,
    out_resp: &mut Option<Vec<u8>>,
) -> usize {

    let req: *mut u8 = null_mut();
    let req_len: &mut usize = &mut 0;

    let resp: *mut u8 = null_mut();
    let resp_len: &mut usize = &mut 0;

    let analysis: *mut u8 = null_mut();
    let analysis_len: &mut usize = &mut 0;

    let req_src_len = req_src.len();
    let req_src_raw = CString::new(req_src).unwrap();

    let mut header_hashmap = HashMap::new();
    for (k, v) in headers {
        let k = k.as_str().to_owned();
        let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
        header_hashmap.entry(k).or_insert_with(Vec::new).push(v)
    }
    let header = serde_json::to_string(&header_hashmap).unwrap();
    let header_len = header.len();
    let header_raw = CString::new(header).unwrap();

    let name_len = match name {
        Some(val) => val.len(),
        None => 0,
    };

    let name_raw: *mut c_char = if name_len > 0 {
        let m = CString::new(name.unwrap()).unwrap();
        m.into_raw()
    } else {    
        null_mut()
    };

    let request_handle = lib::PROCESS_REQUEST(
        handler,
        name_raw,
        name_len,
        header_raw.as_ptr(),
        header_len,
        req_src_raw.as_ptr(),
        req_src_len,
        &resp,
        resp_len,
        &req,
        req_len,
        &analysis,
        analysis_len,
    );

    debug!("inigo-rs: request response, {:?}, {}", resp, resp_len);
    debug!("inigo-rs: request mutation, {:?}, {}", req, req_len);
    debug!("inigo-rs: request analysis, {:?}, {}", analysis, analysis_len);

    // response
    if !resp.is_null() {
        *out_resp = Some(unsafe { std::slice::from_raw_parts_mut(resp, *resp_len) }.to_owned());
        dispose_handle(request_handle);
        return 0;
    } 

    // request mutation
    if !req.is_null() {
        *out_req = Some(unsafe { std::slice::from_raw_parts_mut(req, *req_len) }.to_owned());
    } 

    // analysis
    if !analysis.is_null() {
        let raw = unsafe { std::slice::from_raw_parts_mut(analysis, *analysis_len) }.to_owned();
        let res = String::from_utf8_lossy(raw.as_slice()).into_owned();
        *out_scalars = Some(res.split(',').map(ToString::to_string).collect());
    }

    // reown name_raw pointer
    if !name_raw.is_null() {
        unsafe { let _ = CString::from_raw(name_raw); };
    }

    dispose_pinner(request_handle);
    return request_handle;
}

fn dispose_handle(handle: usize) {
    lib::DISPOSE_HANDLE(handle);
}

fn dispose_pinner(handle: usize) {
    lib::DISPOSE_PINNER(handle);
}

fn get_file_extension() -> &'static str {
    match sys_info::os_type().unwrap().as_str() {
        "Linux" => "so",
        "Darwin" => "dylib",
        "Windows" => "dll",
        _ => "so",
    }
}

pub(crate) fn to_raw(val: &str) -> *const c_char {
    if val.len() == 0 {
        return null();
    }
    return CString::new(val.to_owned()).unwrap().into_raw();
}

pub(crate) fn free_raw(val: *const c_char)  {
    if val.is_null() {
        return;
    }
    unsafe { let _ = CString::from_raw(val as *mut c_char); };
}

pub fn download_library() {
    let os = match sys_info::os_type().unwrap().as_str() {
        "Linux" => "linux",
        "Darwin" => "darwin",
        "Windows" => "windows",
        _ => "unknown",
    };

    let platform = match sysinfo::System::cpu_arch().as_str() {
        "arm64" => "arm64",
        "aarch64" => "arm64",
        "amd64" => "amd64",
        "x86_64" => "amd64",
        _ => "unknown",
    };

    let url = format!(
        "https://github.com/inigolabs/artifacts/releases/latest/download/inigo-{}-{}.{}",
        os, platform, get_file_extension(),
    );

    if !std::path::Path::new(lib::INIGO_LIB_PATH.as_str()).exists() {
        info!("downloading inigo library from {} to {}", &url, lib::INIGO_LIB_PATH.as_str());
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60 * 30))
            .build()
            .unwrap();
    
        let resp = client.get(url).send().unwrap().bytes().unwrap();
        let mut out = std::fs::File::create(lib::INIGO_LIB_PATH.as_str()).unwrap();
        std::io::copy(&mut resp.as_ref(), &mut out).unwrap();
    }
}