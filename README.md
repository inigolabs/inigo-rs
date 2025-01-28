<br />
<div align="center">
  <img src="https://raw.githubusercontent.com/inigolabs/inigo-rs/master/docs/inigo.svg">
  <img height="25" src="https://raw.githubusercontent.com/inigolabs/inigo-rs/master/docs/rust.svg">

  <p align="center">
    GraphQL for Platform Teams
    <br />
    <a href="https://inigo.io">Home</a>
    ·
    <a href="https://docs.inigo.io/">Docs</a>
    ·
    <a href="https://github.com/inigolabs/inigo-rs/issues">Issues</a>
    ·
    <a href="https://slack.inigo.io/">Slack</a>
  </p>
</div>

### Overview
Gain instant monitoring and protection into GraphQL APIs. Unblock platform teams and accelerate GraphQL adoption.
Inigo's platform integration offers GraphQL Security, Analytics, Rate-limiting, Access Control and more.  

This package is the Inigo plugin for the Apollo Rust Router

### Integration

1. Import the Inigo library in your Cargo.toml

```sh
cargo add inigo-rs
```

2. a. Setup Inigo plugin (without registry)
```rs
use apollo_router::register_plugin;
use inigo_rs::Middleware;

register_plugin!("inigo", "middleware", Middleware);

fn main() {
    match apollo_router::main() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
```

2. b. Setup Inigo plugin (with registry)
```rs
use apollo_router::register_plugin;
use inigo_rs::registry::InigoRegistry;
use inigo_rs::Middleware;

register_plugin!("inigo", "middleware", Middleware);

fn main() {
    match InigoRegistry::new(None).and(apollo_router::main()) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
```

3. Configure the plugin
```yaml
plugins:
  inigo.middleware:
    token: "your-inigo-service-token"
```

Tip: It can also be an environment variable
```yaml
plugins:
  inigo.middleware:
    token: "${env.INIGO_SERVICE_TOKEN}"
```

4. a. Automatic FFI library loading
Inigo Rust Router will automatically download the Inigo library from the Inigo service. Only if configured.
```yaml
plugins:
  inigo.middleware:
    token: "${env.INIGO_SERVICE_TOKEN}"
    auto_download_library: true
```

4. b Manual FFI library loading
Place a copy of [Inigo lib](https://github.com/inigolabs/artifacts/releases) file in the docker and set this env variable. For example:
```
INIGO_LIB_PATH=/inigo-linux-amd64.so # Change depending on path/file name (platform and architecture)
```

### Documentation
* [Docs](https://docs.inigo.io/)
* [Integration](https://docs.inigo.io/product/agent_installation/ruby_on_rails)
* [Example](https://github.com/inigolabs/inigo-rs/tree/master/examples)

### Contributing
Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

### License
Distributed under the MIT License.
