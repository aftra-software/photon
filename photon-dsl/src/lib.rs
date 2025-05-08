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
use std::sync::{Mutex, OnceLock};

#[derive(Clone)]
pub struct Config {
    pub verbose: bool,
    pub debug: bool,
}

pub type DslFunc = Box<dyn Fn(&mut DSLStack) -> Result<(), ()> + Send + Sync>;

pub struct DslFunction {
    pub(crate) func: DslFunc,
    pub(crate) params: usize,
}

impl DslFunction {
    pub fn new(params: usize, func: DslFunc) -> Self {
        DslFunction { func, params }
    }
}

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
    use rustc_hash::FxHashMap;

    use crate::parser::compile_expression_validated;

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
        set_config(Config {
            verbose: true,
            debug: true,
        });
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

        functions.insert(
            "contains".into(),
            DslFunction::new(
                2,
                Box::new(|stack: &mut DSLStack| {
                    let needle = stack.pop_string()?;
                    let haystack = stack.pop_string()?;
                    stack.push(Value::Boolean(haystack.contains(&needle)));
                    Ok(())
                }),
            ),
        );

        let compiled = compile_expression("contains(\"Hello World!\", \"Hello\")");
        assert!(compiled.is_ok());

        let res = compiled.unwrap().execute(&NoVariables, &functions);
        assert!(res.is_ok());
        assert!(res.unwrap() == Value::Boolean(true));

        let compiled = compile_expression_validated("\"hello\" + \" world\"", &functions);
        assert!(compiled.is_ok());

        let res = compiled.unwrap().execute(&NoVariables, &functions);
        assert!(res.is_ok());
        println!("{:?}", res);
        assert!(res.unwrap() == Value::String(String::from("hello world")));
    }

    #[test]
    fn too_many_arguments() {
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

        functions.insert(
            "contains".into(),
            DslFunction::new(
                2,
                Box::new(|stack: &mut DSLStack| {
                    let needle = stack.pop_string()?;
                    let haystack = stack.pop_string()?;
                    stack.push(Value::Boolean(haystack.contains(&needle)));
                    Ok(())
                }),
            ),
        );

        // This expression should fail to compile, since the `contains` function takes only 2 parameters
        let compiled = compile_expression_validated(
            "contains(\"Hello World!\", \"Hello\", \"Hi\")",
            &functions,
        );
        assert!(compiled.is_err());
    }
}
