pub mod dsl;
pub mod parser;

use std::sync::OnceLock;
use dsl::DSLStack;
use rustc_hash::FxHashMap;

pub struct Config {
    pub verbose: bool,
    pub debug: bool,
}

pub type DslFunc = Box<dyn Fn(&mut DSLStack) -> Result<(), ()> + Send + Sync>;
pub static GLOBAL_FUNCTIONS: OnceLock<FxHashMap<String, DslFunc>> = OnceLock::new();

static CONFIG: OnceLock<Config> = OnceLock::new();

// Must be ran before anything else
pub fn set_config(config: Config) {
    let _ = CONFIG.set(config);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // TODO: Add tests here
        //let result = add(2, 2);
        //assert_eq!(result, 4);
    }
}
