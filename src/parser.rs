use apollo_router::graphql;
use std::collections::{HashSet, HashMap};
use serde_json_bytes::{ByteString, Value};

pub fn response_counts(resp: &graphql::Response, scalars: HashSet<String>) -> HashMap<ByteString, usize> {
    let mut counts = HashMap::new();
    counts.insert("errors".into(), resp.errors.len());
    if resp.data.is_none() {
        counts.insert("total_objects".into(), 0);
        return counts;
    }

    counts.insert("total_objects".into(), count_total_objects(resp.data.as_ref().unwrap(), scalars));
    return counts
}

fn count_total_objects(response: &Value, scalars: HashSet<String>) -> usize {
    struct KeyValuePair<'a> {
        key: ByteString,
        val: &'a Value,
    }

    let start = KeyValuePair {
        key: "data".into(),
        val: response,
    };

    let mut total = 0;
    let mut stack: Vec<KeyValuePair> = vec![start];

    while !stack.is_empty() {
        let current = stack.pop().unwrap();
        let key = current.key.clone();
        let val = current.val;

        if scalars.contains(key.as_str()) {
            continue;
        }

        match val {
            Value::Object(obj) => {
                total += 1;
                for (k, v) in obj {
                    let key: ByteString = (key.as_str().to_owned() + "." + k.clone().as_str()).into();
                    stack.push(KeyValuePair { key, val: &v });
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    stack.push(KeyValuePair { key: key.clone(), val: &v });
                }
            }
            _ => {}
        }
    }

    return total;
}
