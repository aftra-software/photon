// Defined before any imports/module declarations because of weird macro scoping
macro_rules! debug {
    ($fmt:expr $(, $($arg:tt)*)?) => {
        if get_config().debug {
            println!($fmt, $($($arg)*)?);
        }
    };
}

macro_rules! verbose {
    ($fmt:expr $(, $($arg:tt)*)?) => {
        if get_config().verbose {
            println!($fmt, $($($arg)*)?);
        }
    };
}

pub mod dsl;
pub mod parser;

use dsl::DSLStack;
use rustc_hash::FxHashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Clone)]
pub struct Config {
    pub verbose: bool,
    pub debug: bool,
}

pub type DslFunc = Box<dyn Fn(&mut DSLStack) -> Result<(), ()> + Send + Sync>;
pub static GLOBAL_FUNCTIONS: OnceLock<FxHashMap<String, DslFunc>> = OnceLock::new();

static CONFIG: OnceLock<Mutex<Config>> = OnceLock::new();

pub(crate) fn get_config() -> Config {
    CONFIG.get().unwrap().lock().unwrap().clone()
}

// Must be ran before anything else
pub fn set_config(config: Config) {
    let _ = CONFIG.set(Mutex::from(config));
}

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn it_works() {
        // TODO: Add tests here
        //let result = add(2, 2);
        //assert_eq!(result, 4);
    }
}
