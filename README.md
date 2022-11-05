<br />
<div align="center">
  <img src="https://raw.githubusercontent.com/inigolabs/inigo-rs/master/docs/inigo.svg">
  <img height="25" src="https://raw.githubusercontent.com/inigolabs/inigo-rs/master/docs/rust.svg">

  <p align="center">
    GraphQL Middleware
    <br />
    <a href="https://docs.inigo.io"><strong>Explore the docs »</strong></a>
    <br /> <br />
    <a href="https://inigo.io">Homepage</a>
    ·
    <a href="https://github.com/inigolabs/inigo-rs/tree/master/examples">View an example</a>
    ·
    <a href="https://github.com/inigolabs/inigo-rs/issues">Report Bug</a>
  </p>
</div>

---

[Inigo](https://inigo.io) integration for [Apollo Router](https://www.apollographql.com/docs/router/customizations/native/)

# Quickstart

1. Register a plugin

```rs
use anyhow::Result;
use apollo_router::register_plugin;
use inigo_rs::Middleware;

register_plugin!("inigo", "middleware", Middleware);

fn main() -> Result<()> {
    apollo_router::main()
}

```

NOTE: Do not forget to import Inigo in your Cargo.toml

```
[dependencies]
inigo-rs = "0.1.9"
```

2. Configure a plugin

```yaml
plugins:
  inigo.middleware:
    jwt_header: "authorization"
    token: "your-inigo-service-token"
```
