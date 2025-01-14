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

fn init_functions() -> FxHashMap<String, DslFunc> {
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
            let reg = Regex::new(&patt).map_err(|_| ())?; // TODO: Don't map err, use some proper DSL error handling
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
    functions.insert(
        "hex_decode".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            let decoded_vec =  base16ct::mixed::decode_vec(inp).map_err(|_| ())?; // TODO: Don't map err, use some proper DSL error handling
            let decoded_str = String::from_utf8_lossy(&decoded_vec);
            stack.push(Value::String(String::from(decoded_str)));
            Ok(())
        })
    );

    functions
}

pub fn initialize() {
    if GLOBAL_FUNCTIONS.get().is_some() {
        return; // Don't waste time 
    }

    let _ = BRACKET_PATTERN.set(Mutex::from(Regex::new("\\{\\{[^{}]*}}").unwrap()));
    let functions = init_functions();

    GLOBAL_FUNCTIONS.set(Mutex::from(functions)).ok().unwrap();
}

#[cfg(test)]
mod tests {
    use photon_dsl::dsl::{Value, VariableContainer};
    use photon_dsl::parser::compile_expression;

    use super::*;

    struct NoVariables;
    impl VariableContainer for NoVariables {
        fn contains_key(&self, _: &str) -> bool {
            false
        }
        fn get(&self, _: &str) -> Option<Value> {
            None
        }
    }

    fn test_expression(fns: &FxHashMap<String, DslFunc>, expr: &str) -> bool {
        let compiled = compile_expression(expr);
        assert!(compiled.is_ok());

        let res = compiled.unwrap().execute(&NoVariables, &fns);
        assert!(res.is_ok());
        res.unwrap() == Value::Boolean(true)
    }

    #[test]
    fn test_functions() {
        photon_dsl::set_config(photon_dsl::Config { verbose: true, debug: true });
        let functions: FxHashMap<String, DslFunc> = init_functions();

        assert!(test_expression(&functions, "hex_decode('7072756661313233') == 'prufa123'"));
        assert!(test_expression(&functions, "len('abcdef') == 6"));
        assert!(test_expression(&functions, "to_lower('ABCdef') == 'abcdef'"));
        assert!(test_expression(&functions, "to_lower('ABCdef') == tolower('ABCdef')"));
        assert!(test_expression(&functions, "contains('123ABC123', 'ABC') && !contains('123', 'ABC')"));
        assert!(test_expression(&functions, "regex('1\\\\w*2', 'blabla1blabla2')"));
        assert!(test_expression(&functions, "md5('test') == '098f6bcd4621d373cade4e832627b4f6'"));
    }
}
