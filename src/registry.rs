/*
MIT License

Copyright (c) 2022 The Guild
Copyright (c) 2023 Inigo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use anyhow::Result;
use apollo_router::graphql;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use std::env;
use std::io::Write;
use std::thread;

#[derive(Debug, Clone)]
pub struct InigoRegistry {
    endpoint: String,
    key: String,
    file_name: String,
    version: u32,
}

pub struct InigoRegistryConfig {
    endpoint: Option<String>,
    key: Option<String>,
    poll_interval: Option<u64>,
    enabled: Option<bool>,
}

impl InigoRegistry {
    pub fn new(user_config: Option<InigoRegistryConfig>) -> Result<()> {
        let mut config = InigoRegistryConfig {
            endpoint: None,
            key: None,
            poll_interval: None,
            enabled: None,
        };

        // Pass values from user's config
        if let Some(user_config) = user_config {
            config.endpoint = user_config.endpoint;
            config.key = user_config.key;
            config.poll_interval = user_config.poll_interval;
            config.enabled = user_config.enabled;
        }

        // Pass values from environment variables if they are not set in the user's config
        if config.enabled.is_none() {
            // set registry to be enabled by default
            config.enabled = Some(true);

            if let Ok(enabled) = env::var("INIGO_REGISTRY_ENABLED") {
                config.enabled = Some(
                    enabled
                        .parse()
                        .expect("failed to parse INIGO_REGISTRY_ENABLED"),
                );
            }
        }

        if !config.enabled.unwrap() {
            println!("You're not using GraphQL Inigo as the source of schema.");
            return Ok(());
        }

        if config.endpoint.is_none() {
            if let Ok(endpoint) = env::var("INIGO_REGISTRY_URL") {
                config.endpoint = Some(endpoint);
            }
        }

        if config.endpoint.is_none() {
            config.endpoint = Some("https://app.inigo.io/agent/query".to_string());
        }

        if config.key.is_none() {
            if let Ok(key) = env::var("INIGO_SERVICE_TOKEN") {
                config.key = Some(key);
            }
        }

        if config.poll_interval.is_none() {
            if let Ok(poll_interval) = env::var("INIGO_ROUTER_POLL_INTERVAL") {
                config.poll_interval = Some(
                    poll_interval
                        .parse()
                        .expect("failed to parse INIGO_ROUTER_POLL_INTERVAL"),
                );
            }
        }

        // Resolve values
        let endpoint = config.endpoint.unwrap_or_else(|| "".to_string());
        let key = config.key.unwrap_or_else(|| "".to_string());
        let poll_interval: u64 = match config.poll_interval {
            Some(value) => value,
            None => 30,
        };

        // Throw if endpoint is empty
        if endpoint.is_empty() {
            println!("You're not using GraphQL Inigo as the source of schema.");
            println!("Reason: service url is empty.",);
            return Ok(());
        }

        // Throw if key is empty
        if key.is_empty() {
            println!("You're not using GraphQL Inigo as the source of schema.");
            println!("Reason: could not find INIGO_SERVICE_TOKEN environment variables.",);
            return Ok(());
        }

        let file_name = get_schema_path();
        println!("Following schema will be wached: {}", file_name.as_str());
        env::set_var("APOLLO_ROUTER_SUPERGRAPH_PATH", file_name.clone());
        env::set_var("APOLLO_ROUTER_HOT_RELOAD", "true");

        let mut registry = InigoRegistry {
            endpoint,
            key,
            file_name,
            version: 0,
        };
        match registry.initial_supergraph() {
            Ok(_) => {
                println!("Successfully fetched and saved supergraph from GraphQL Inigo");
            }
            Err(e) => eprintln!("Could not get supergraph schema from registry: {}", e),
        }

        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(poll_interval));
            registry.poll()
        });

        Ok(())
    }

    fn fetch_supergraph(&mut self) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::builder()
            .build()
            .map_err(|err| err.to_string())?;
        let mut headers = http::HeaderMap::new();

        headers.insert("Authorization", self.key.parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());

        let resp = client
            .post(self.endpoint.as_str())
            .headers(headers)
            .body(format!("{{\"query\":\"query FetchFederatedSchema {{registry {{ federatedSchema(afterVersion: {}) {{ status version schema      }}}}}}\"}}",self.version))
            .send()
            .map_err(|e| e.to_string())?;

        if resp.status().as_u16() != 200 {
            return Ok(None);
        }

        let response: FederatedSchemaResponse = serde_json::from_str(resp.text()?.as_str())?;
        if response.errors.len() > 0 {
            return Err(response
                .errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<&str>>()
                .join(",")
                .into())
            .into();
        }

        let registry = response.data.unwrap().registry;
        match registry.federated_schema.status.as_str() {
            "unchanged" => Ok(None),
            "missing" => Err("schema is not available in the registry".into()),
            "updated" => {
                self.version = registry.federated_schema.version;
                return Ok(registry.federated_schema.schema);
            }

            _ => Err("unknown status".into()),
        }
    }

    fn initial_supergraph(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self.fetch_supergraph()?;

        match resp {
            Some(supergraph) => {
                let mut file =
                    std::fs::File::create(self.file_name.clone()).map_err(|e| e.to_string())?;
                file.write_all(supergraph.as_bytes())
                    .map_err(|e| e.to_string())?;
            }
            None => {
                return Err("Failed to fetch supergraph".into());
            }
        }

        Ok(())
    }

    fn poll(&mut self) {
        match self.fetch_supergraph() {
            Ok(new_supergraph) => {
                if let Some(new_supergraph) = new_supergraph {
                    let current_file = std::fs::read_to_string(self.file_name.clone())
                        .expect("Could not read file");
                    let current_supergraph_hash = hash(current_file.as_bytes());

                    let new_supergraph_hash = hash(new_supergraph.as_bytes());

                    if current_supergraph_hash != new_supergraph_hash {
                        println!("New supergraph detected!");
                        std::fs::write(self.file_name.clone(), new_supergraph)
                            .expect("Could not write file");
                    }
                }
            }
            Err(e) => eprintln!("{}", e),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
struct FederatedSchemaResponse {
    data: Option<Registry>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    errors: Vec<graphql::Error>,
}

#[derive(Deserialize, Debug, Clone)]
struct Registry {
    registry: FederatedSchema,
}

#[derive(Deserialize, Debug, Clone)]
struct FederatedSchema {
    #[serde(rename = "federatedSchema")]
    federated_schema: Schema,
}

#[derive(Deserialize, Debug, Clone)]
struct Schema {
    status: String,
    schema: Option<String>,
    version: u32,
}

fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:X}", hasher.finalize())
}

fn get_schema_path() -> String {
    let mut path = "supergraph-schema.graphql".to_string();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match &arg[..] {
            "-s" | "--supergraph" => {
                if let Some(arg_config) = args.next() {
                    path = arg_config;
                }
            }
            _ => {}
        }
    }

    return path;
}
