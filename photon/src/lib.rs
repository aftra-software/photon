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

mod cache;
mod http;
pub mod template;
pub mod template_executor;
pub mod template_loader;

use std::sync::Mutex;

use http::BRACKET_PATTERN;
use md5::{Digest, Md5};
use photon_dsl::{
    dsl::{DSLStack, Value},
    DslFunc, GLOBAL_FUNCTIONS,
};
use regex::Regex;
use rustc_hash::FxHashMap;

#[derive(Clone)]
pub struct Config {
    pub verbose: bool,
    pub debug: bool,
}

lazy_static::lazy_static! {
    static ref CONFIG: Mutex<Config> = {
        Mutex::from(Config {
            debug: false,
            verbose: false,
        })
    };
}

pub(crate) fn get_config() -> Config {
    CONFIG.lock().unwrap().clone()
}

pub fn set_debug(state: bool) {
    CONFIG.lock().unwrap().debug = state;
}

pub fn set_verbose(state: bool) {
    CONFIG.lock().unwrap().verbose = state;
}

pub fn set_config(config: Config) {
    photon_dsl::set_config(photon_dsl::Config {
        verbose: config.verbose,
        debug: config.debug,
    });

    *CONFIG.lock().unwrap() = config;
}

pub fn add_global_function(name: &str, f: DslFunc) {
    GLOBAL_FUNCTIONS
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .insert(name.into(), f);
}

pub fn initialize() {
    let _ = BRACKET_PATTERN.set(Mutex::from(Regex::new("\\{\\{[^{}]*}}").unwrap()));

    let mut functions: FxHashMap<String, DslFunc> = FxHashMap::default();

    functions.insert(
        "md5".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            let hash = base16ct::lower::encode_string(&Md5::digest(inp));
            stack.push(Value::String(hash));
            Ok(())
        }),
    );
    functions.insert(
        "regex".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            let patt = stack.pop_string()?;
            let reg = Regex::new(&patt).map_err(|_| ())?;
            stack.push(Value::Boolean(reg.is_match(&inp)));
            Ok(())
        }),
    );
    functions.insert(
        "contains".into(),
        Box::new(|stack: &mut DSLStack| {
            let needle = stack.pop_string()?;
            let haystack = stack.pop_string()?;
            stack.push(Value::Boolean(haystack.contains(&needle)));
            Ok(())
        }),
    );
    functions.insert(
        "tolower".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            stack.push(Value::String(inp.to_lowercase()));
            Ok(())
        }),
    );
    functions.insert(
        "to_lower".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            stack.push(Value::String(inp.to_lowercase()));
            Ok(())
        }),
    );
    functions.insert(
        "len".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            stack.push(Value::Int(inp.len() as i64));
            Ok(())
        }),
    );

    GLOBAL_FUNCTIONS.set(Mutex::from(functions)).ok().unwrap();
}
