use apollo_router::graphql::{Request, Response};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use http::HeaderMap;
use inigo_rs::{Inigo, SidecarConfig, CREATE_MOCK};
use serde_json_bytes::{ByteString, Map, Value};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::ptr::null;
use std::time::Duration;

fn handle_responce(c: &mut Criterion) {
    let file_path = "./benches/schema.graphql";
    let mut file = File::open(file_path).unwrap();

    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();

    let schema = CString::new(content).unwrap().into_raw();
    let i = Inigo::new(CREATE_MOCK(&SidecarConfig {
        debug: false,
        egress_url: null(),
        service: null(),
        token: null(),
        name: null(),
        runtime: null(),
        schema,
        gateway: null(),
        disable_response_data: true,
    }));

    let req = &mut Request::builder()
        .operation_name("stuff")
        .query("query stuff { films { director } }")
        .build();

    let mut payload = ",{\"director\":\"1234\"}".repeat(50000); // ~1MB
    payload.remove(0);
    payload = format!("{{\"data\":{{\"films\":[{}]}}}}", payload);

    let json: Map<ByteString, Value> = serde_json::from_str(&payload).unwrap();

    let data: Value = json.get("data").unwrap().to_owned();

    let mut resp = black_box(Response::builder().data(data).build());

    let mut group = c.benchmark_group("inigo");
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("handle_response", |b| {
        b.iter(|| {
            i.process_request(req, &HeaderMap::new());
            i.process_response(&mut resp)
        })
    });
    group.finish();

    let serialized = serde_json::to_string(&resp).unwrap();
    assert_eq!(payload, serialized);
}

criterion_main!(benches);
criterion_group! {
   name = benches;
   config = Criterion::default().measurement_time(Duration::from_secs(60));
   targets = handle_responce
}
