use apollo_router::register_plugin;
use inigo_rs::registry::InigoRegistry;
use inigo_rs::Middleware;

register_plugin!("inigo", "middleware", Middleware);

fn main() {
    // Initialize the Inigo Registry and start the Apollo Router
    match InigoRegistry::new(None).and(apollo_router::main()) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
