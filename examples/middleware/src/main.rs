use anyhow::Result;
use apollo_router::register_plugin;
use inigo_rs::Middleware;
use inigo_rs::registry::InigoRegistry;

register_plugin!("inigo", "middleware", Middleware);

fn main() -> Result<()> {
    // Initialize the Inigo Registry and start the Apollo Router
    match InigoRegistry::new(None).and(apollo_router::main()) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
    apollo_router::main()
}
