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

use base64::{prelude::BASE64_STANDARD, Engine};
use md5::{Digest, Md5};
use photon_dsl::{
    dsl::{DSLStack, Value},
    DslFunction,
};
use rand::Rng;
use regex::Regex;
use rustc_hash::FxHashMap;

#[derive(Clone)]
pub struct Config {
    pub verbose: bool,
    pub debug: bool,
}

pub struct PhotonContext {
    functions: FxHashMap<String, DslFunction>,
}

impl PhotonContext {
    pub fn add_function(&mut self, name: &str, func: DslFunction) {
        self.functions.insert(String::from(name), func);
    }
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

fn init_functions() -> FxHashMap<String, DslFunction> {
    let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

    functions.insert(
        "md5".into(),
        DslFunction::new(
            1,
            Box::new(|stack: &mut DSLStack| {
                let inp = stack.pop_string()?;
                let hash = base16ct::lower::encode_string(&Md5::digest(inp));
                Ok(Value::String(hash))
            }),
        ),
    );
    functions.insert(
        "regex".into(),
        DslFunction::new(
            2,
            Box::new(|stack: &mut DSLStack| {
                let inp = stack.pop_string()?;
                let patt = stack.pop_string()?;
                let reg = Regex::new(&patt).map_err(|_| ())?; // TODO: Don't map err, use some proper DSL error handling
                Ok(Value::Boolean(reg.is_match(&inp)))
            }),
        ),
    );
    functions.insert(
        "contains".into(),
        DslFunction::new(
            2,
            Box::new(|stack: &mut DSLStack| {
                let needle = stack.pop_string()?;
                let haystack = stack.pop_string()?;
                Ok(Value::Boolean(haystack.contains(&needle)))
            }),
        ),
    );
    functions.insert(
        "tolower".into(),
        DslFunction::new(
            1,
            Box::new(|stack: &mut DSLStack| {
                let inp = stack.pop_string()?;
                Ok(Value::String(inp.to_lowercase()))
            }),
        ),
    );
    functions.insert(
        "to_lower".into(),
        DslFunction::new(
            1,
            Box::new(|stack: &mut DSLStack| {
                let inp = stack.pop_string()?;
                Ok(Value::String(inp.to_lowercase()))
            }),
        ),
    );
    functions.insert(
        "len".into(),
        DslFunction::new(
            1,
            Box::new(|stack: &mut DSLStack| {
                let inp = stack.pop_string()?;
                Ok(Value::Int(inp.len() as i64))
            }),
        ),
    );
    functions.insert(
        "hex_decode".into(),
        DslFunction::new(
            1,
            Box::new(|stack: &mut DSLStack| {
                let inp = stack.pop_string()?;
                let decoded_vec = base16ct::mixed::decode_vec(inp).map_err(|_| ())?; // TODO: Don't map err, use some proper DSL error handling
                let decoded_str = String::from_utf8_lossy(&decoded_vec);
                Ok(Value::String(String::from(decoded_str)))
            }),
        ),
    );
    functions.insert(
        "base64_decode".into(),
        DslFunction::new(
            1,
            Box::new(|stack: &mut DSLStack| {
                let inp = stack.pop_string()?;
                let decoded_vec = BASE64_STANDARD.decode(inp).map_err(|_| ())?; // TODO: Don't map err, use some proper DSL error handling
                let res = String::from_utf8(decoded_vec); // TODO: possibly needs to return raw bytes (not supported in DSL right now) instead of valid UTF-8
                match res {
                    Ok(decoded_str) => Ok(Value::String(decoded_str)),
                    Err(_) => Err(()),
                }
            }),
        ),
    );
    functions.insert(
        "rand_int".into(),
        DslFunction::new(
            2,
            Box::new(|stack: &mut DSLStack| {
                let max = stack.pop_int()?;
                let min = stack.pop_int()?;

                let rand_value = rand::thread_rng().gen_range(min..max);

                Ok(Value::Int(rand_value))
            }),
        ),
    );

    functions
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

    fn test_expression(fns: &FxHashMap<String, DslFunction>, expr: &str) -> bool {
        let compiled = compile_expression(expr);
        assert!(compiled.is_ok());

        let res = compiled.unwrap().execute(&NoVariables, &fns);
        assert!(res.is_ok());
        res.unwrap() == Value::Boolean(true)
    }

    #[test]
    fn test_functions() {
        photon_dsl::set_config(photon_dsl::Config {
            verbose: true,
            debug: true,
        });
        let functions: FxHashMap<String, DslFunction> = init_functions();

        assert!(test_expression(
            &functions,
            "hex_decode('7072756661313233') == 'prufa123'"
        ));
        assert!(test_expression(&functions, "len('abcdef') == 6"));
        assert!(test_expression(
            &functions,
            "to_lower('ABCdef') == 'abcdef'"
        ));
        assert!(test_expression(
            &functions,
            "to_lower('ABCdef') == tolower('ABCdef')"
        ));
        assert!(test_expression(
            &functions,
            "contains('123ABC123', 'ABC') && !contains('123', 'ABC')"
        ));
        assert!(test_expression(
            &functions,
            "regex('1\\\\w*2', 'blabla1blabla2')"
        ));
        assert!(test_expression(
            &functions,
            "md5('test') == '098f6bcd4621d373cade4e832627b4f6'"
        ));
        assert!(test_expression(
            &functions,
            "base64_decode('YmFzZTY0IHRlc3Qgc3RyaW5n') == 'base64 test string'"
        ));
        // I know these are random, but 33% chance + mainly as as sanity check
        assert!(test_expression(&functions, "rand_int(1, 3) >= 1"));
        assert!(test_expression(&functions, "rand_int(1, 3) <= 2"));
    }
}
