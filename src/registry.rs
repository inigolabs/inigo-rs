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

use anyhow::{anyhow, Result};
use sha2::Digest;
use sha2::Sha256;
use std::env;
use std::io::Write;
use std::thread;
use serde_json::{Value};
use jsonpath::Selector;

#[derive(Debug, Clone)]
pub struct InigoRegistry {
    endpoint: String,
    key: String,
    file_name: String,
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
            enabled:None,
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
            if let Ok(enabled) = env::var("INIGO_REGISTRY_ENABLED") {
                config.enabled = Some(enabled.parse().expect("failed to parse INIGO_REGISTRY_ENABLED"));
            }
        }

        if config.enabled.is_none() || !config.enabled.unwrap() {
            println!("You're not using GraphQL Inigo as the source of schema.");
            return  Ok(());
        }

        if config.endpoint.is_none() {
            if let Ok(endpoint) = env::var("INIGO_SERVICE_URL") {
                config.endpoint = Some(endpoint);
            }
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

        // In case of an endpoint and an key being empty, we don't start the polling and skip the registry
        if endpoint.is_empty() && key.is_empty() {
            println!("You're not using GraphQL Inigo as the source of schema.");
            println!(
                "Reason: could not find INIGO_SERVICE_TOKEN and INIGO_SERVICE_URL environment variables.",
            );
            return Ok(());
        }

        // Throw if endpoint is empty
        if endpoint.is_empty() {
            return Err(anyhow!("environment variable INIGO_SERVICE_URL not found",));
        }

        // Throw if key is empty
        if key.is_empty() {
            return Err(anyhow!("environment variable INIGO_SERVICE_TOKEN not found"));
        }

        let file_name = "supergraph-schema.graphql".to_string();
        env::set_var("APOLLO_ROUTER_SUPERGRAPH_PATH", file_name.clone());
        env::set_var("APOLLO_ROUTER_HOT_RELOAD", "true");

        let mut registry = InigoRegistry {
            endpoint,
            key,
            file_name,
        };

        match registry.initial_supergraph() {
            Ok(_) => {
                println!("Successfully fetched and saved supergraph from GraphQL Inigo");
            }
            Err(e) => {
                eprintln!("{}", e.as_str());
                // std::process::exit(1);
            }
        }

        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(poll_interval));
            registry.poll()
        });

        Ok(())
    }

    fn fetch_supergraph(&mut self) -> Result<Option<String>, String> {
        let client = reqwest::blocking::Client::builder()
            .build()
            .map_err(|err| err.to_string())?;
        let mut headers = http::HeaderMap::new();

        headers.insert("Authorization",  self.key.parse().unwrap());
        headers.insert("Content-Type",  "application/json".parse().unwrap());

        //
        let resp = client
            .post(  self.endpoint.as_str())
            .headers(headers)
            .body("{\"query\":\"query composedSchema { gatewayInfo { composedSchema }}\"}")

            .send()
            .map_err(|e| e.to_string())?;

        if resp.status().as_u16() != 200 {
            return Ok(None);
        }

        let json: Value = serde_json::from_str(resp.text().unwrap().as_str()).unwrap();

        let selector = Selector::new("$.data.gatewayInfo.composedSchema").unwrap();

        let schema: Vec<&str> = selector.find(&json).map(|t| t.as_str().unwrap()).collect();
        if schema.len() == 0 {
            return Ok(None);
        }

        Ok(Some(schema[0].to_string()))
    }

    fn initial_supergraph(&mut self) -> Result<(), String> {
        let resp = self.fetch_supergraph()?;

        match resp {
            Some(supergraph) => {
                let mut file = std::fs::File::create(self.file_name.clone()).map_err(|e| e.to_string())?;
                file.write_all(supergraph.as_bytes())
                    .map_err(|e| e.to_string())?;
            }
            None => {
                return Err("Failed to fetch supergraph".to_string());
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

fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:X}", hasher.finalize())
}