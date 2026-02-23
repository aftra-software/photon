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
mod util;

use dsl::{DSLStack, Value};
use std::sync::{Mutex, OnceLock};

#[derive(Clone)]
pub struct Config {
    pub verbose: bool,
    pub debug: bool,
}

pub type DslFunc = Box<dyn Fn(&mut DSLStack) -> Result<Value, ()> + Send + Sync>;

pub struct DslFunction {
    pub(crate) func: DslFunc,
    pub(crate) params: usize,
}

impl DslFunction {
    pub fn new(params: usize, func: DslFunc) -> Self {
        DslFunction { func, params }
    }

    pub fn execute(&self, stack: &mut dsl::DSLStack) -> Result<Value, ()> {
        (self.func)(stack)
    }

    pub fn params(&self) -> usize {
        self.params
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
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

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

    fn side_effect_function(counter: Arc<AtomicUsize>, return_value: bool) -> DslFunction {
        DslFunction::new(
            1,
            Box::new(move |stack: &mut DSLStack| {
                let _ = stack.pop()?;
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(Value::Boolean(return_value))
            }),
        )
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
                    Ok(Value::Boolean(haystack.contains(&needle)))
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
                    Ok(Value::Boolean(haystack.contains(&needle)))
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

    #[test]
    fn short_circuit_and() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();
        functions.insert(
            "side_effect".into(),
            side_effect_function(counter.clone(), true),
        );

        let compiled = compile_expression_validated("false && side_effect(1)", &functions).unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(false));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn short_circuit_or() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();
        functions.insert(
            "side_effect".into(),
            side_effect_function(counter.clone(), false),
        );

        let compiled = compile_expression_validated("true || side_effect(1)", &functions).unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(true));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn non_short_circuit_and_or() {
        let and_counter = Arc::new(AtomicUsize::new(0));
        let or_counter = Arc::new(AtomicUsize::new(0));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();
        functions.insert(
            "and_side_effect".into(),
            side_effect_function(and_counter.clone(), false),
        );
        functions.insert(
            "or_side_effect".into(),
            side_effect_function(or_counter.clone(), true),
        );

        let compiled_and =
            compile_expression_validated("true && and_side_effect(1)", &functions).unwrap();
        let res_and = compiled_and.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res_and, Value::Boolean(false));
        assert_eq!(and_counter.load(Ordering::SeqCst), 1);

        let compiled_or =
            compile_expression_validated("false || or_side_effect(1)", &functions).unwrap();
        let res_or = compiled_or.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res_or, Value::Boolean(true));
        assert_eq!(or_counter.load(Ordering::SeqCst), 1);
    }
}
