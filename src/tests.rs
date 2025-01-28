
#[cfg(test)]
mod tests {
    use apollo_router::graphql;
    use rstest::*;
    use serde_json_bytes::{ByteString, Value};
    use std::collections::{HashSet, HashMap};
    use crate::parser::response_counts;

    #[rstest]
    #[case(
        r#"{"data":{"key1":"val1","key2":"val2"}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.key1".into(), 1),
            ("data.key2".into(), 1),
            ("errors".into(), 0),
        ]),
        1,
    )]
    #[case(
        r#"{"data":{"key":[]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("errors".into(), 0),
        ]),
        1,
    )]
    #[case(
        r#"{"data":{"key1":[["val1.0","val1.1","val1.2"],["val1.0","val1.1",["v1","v2"]]],"key2":["val2.0","val2.1"]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.key1".into(), 7),
            ("data.key2".into(), 2),
            ("errors".into(), 0),
        ]),
        1,
    )]
    #[case(
        r#"{"data":{"key1":["val1.0","val1.1"],"key2":["val2.0","val2.1"]}}"#,
        HashMap::from([
            ("data".into(), 1),
            ("data.key1".into(), 2),
            ("data.key2".into(), 2),
            ("errors".into(), 0),
        ]),
        1,
    )]
    #[case(
        r#"{"data":[{"key":"val"},{"key":"val"}]}"#,
        HashMap::from([
            ("data".into(), 2),
            ("data.key".into(), 2),
            ("errors".into(), 0),
        ]),
        2,
    )]
    #[case(
        r#"{"data":null}"#,
        HashMap::from([
            ("data".into(), 1),
            ("errors".into(), 0),
        ]),
        0,
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
    5,
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
    5,
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
    5,
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
    12,
    )]

    

    fn count_response(#[case] raw: &str, #[case] expected: HashMap<ByteString, usize>, #[case] total_objects: usize) {
        fn count_response_fields_recursive(hm: &mut HashMap<ByteString, usize>, prefix: &ByteString, val: &Value) -> bool {
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

        let result: graphql::Response = serde_json::from_str(raw).unwrap();
        assert_eq!(count_response_fields(&result), expected);
        assert_eq!(response_counts(&result, HashSet::new()).get("total_objects"), Some(&total_objects));
    }
}
