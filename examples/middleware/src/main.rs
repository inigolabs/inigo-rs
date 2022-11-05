use anyhow::Result;
use apollo_router::register_plugin;
use inigo_rs::Middleware;

register_plugin!("inigo", "middleware", Middleware);

fn main() -> Result<()> {
    apollo_router::main()
}
