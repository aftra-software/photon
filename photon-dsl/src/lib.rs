// TODO: See if there's a nicer way to do this, so that scoping rules still stand
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
pub static GLOBAL_FUNCTIONS: OnceLock<Mutex<FxHashMap<String, DslFunc>>> = OnceLock::new();

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
    use dsl::{Value, VariableContainer};
    use parser::compile_expression;

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

    #[test]
    fn basic_functionality() {
        let mut functions: FxHashMap<String, DslFunc> = FxHashMap::default();

        functions.insert(
            "contains".into(),
            Box::new(|stack: &mut DSLStack| {
                let needle = stack.pop_string()?;
                let haystack = stack.pop_string()?;
                stack.push(Value::Boolean(haystack.contains(&needle)));
                Ok(())
            }),
        );

        let compiled = compile_expression("contains(\"Hello World!\", \"Hello\")");
        assert!(compiled.is_ok());

        let res = compiled.unwrap().execute(&NoVariables, &functions);
        assert!(res.is_ok());
        assert!(res.unwrap() == Value::Boolean(true));
    }
}
