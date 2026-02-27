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

pub type DslFunc = Box<dyn Fn(&mut DSLStack) -> Result<Value, ()>>;

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
        set_config(Config {
            verbose: true,
            debug: true,
        });

        let call_count = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

        let cc = call_count.clone();
        functions.insert(
            "side_effect".into(),
            DslFunction::new(
                1,
                Box::new(move |stack: &mut DSLStack| {
                    let val = stack.pop_bool()?;
                    cc.set(cc.get() + 1);
                    Ok(Value::Boolean(val))
                }),
            ),
        );

        // false && side_effect(true): side_effect should NOT be called
        call_count.set(0);
        let compiled = compile_expression("false && side_effect(true)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(false));
        assert_eq!(
            call_count.get(),
            0,
            "side_effect should not be called when left side of && is false"
        );

        // true && side_effect(false): side_effect SHOULD be called, result is false
        call_count.set(0);
        let compiled = compile_expression("true && side_effect(false)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(false));
        assert_eq!(
            call_count.get(),
            1,
            "side_effect should be called when left side of && is true"
        );

        // true && side_effect(true): side_effect SHOULD be called, result is true
        call_count.set(0);
        let compiled = compile_expression("true && side_effect(true)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(true));
        assert_eq!(call_count.get(), 1);
    }

    #[test]
    fn short_circuit_or() {
        set_config(Config {
            verbose: true,
            debug: true,
        });

        let call_count = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

        let cc = call_count.clone();
        functions.insert(
            "side_effect".into(),
            DslFunction::new(
                1,
                Box::new(move |stack: &mut DSLStack| {
                    let val = stack.pop_bool()?;
                    cc.set(cc.get() + 1);
                    Ok(Value::Boolean(val))
                }),
            ),
        );

        // true || side_effect(false): side_effect should NOT be called
        call_count.set(0);
        let compiled = compile_expression("true || side_effect(false)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(true));
        assert_eq!(
            call_count.get(),
            0,
            "side_effect should not be called when left side of || is true"
        );

        // false || side_effect(true): side_effect SHOULD be called, result is true
        call_count.set(0);
        let compiled = compile_expression("false || side_effect(true)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(true));
        assert_eq!(
            call_count.get(),
            1,
            "side_effect should be called when left side of || is false"
        );

        // false || side_effect(false): side_effect SHOULD be called, result is false
        call_count.set(0);
        let compiled = compile_expression("false || side_effect(false)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(false));
        assert_eq!(call_count.get(), 1);
    }

    #[test]
    fn short_circuit_complex_flow() {
        set_config(Config {
            verbose: true,
            debug: true,
        });

        let call_count = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

        let cc = call_count.clone();
        functions.insert(
            "http".into(),
            DslFunction::new(
                1,
                Box::new(move |stack: &mut DSLStack| {
                    let idx = stack.pop_int()?;
                    cc.set(cc.get() + 1);
                    // Simulate: http(1) = true, http(2) = true, http(3) = false
                    Ok(Value::Boolean(idx != 3))
                }),
            ),
        );

        // http(1) && http(2): both should be called, result true
        call_count.set(0);
        let compiled = compile_expression("http(1) && http(2)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(true));
        assert_eq!(call_count.get(), 2);

        // http(3) && http(1): http(3) returns false, http(1) should NOT be called
        call_count.set(0);
        let compiled = compile_expression("http(3) && http(1)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(false));
        assert_eq!(
            call_count.get(),
            1,
            "http(1) should not be called when http(3) is false"
        );

        // (http(1) && http(2)) || http(3): left side is true, http(3) should NOT be called
        call_count.set(0);
        let compiled = compile_expression("(http(1) && http(2)) || http(3)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(true));
        assert_eq!(
            call_count.get(),
            2,
            "http(3) should not be called when (http(1) && http(2)) is true"
        );

        // (http(3) && http(1)) || http(2): left side is false (http(1) skipped), http(2) should be called
        call_count.set(0);
        let compiled = compile_expression("(http(3) && http(1)) || http(2)").unwrap();
        let res = compiled.execute(&NoVariables, &functions).unwrap();
        assert_eq!(res, Value::Boolean(true));
        assert_eq!(
            call_count.get(),
            2,
            "http(3) and http(2) should be called, http(1) skipped"
        );
    }
}
