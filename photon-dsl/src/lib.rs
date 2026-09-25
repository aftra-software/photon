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

use dsl::{CallArgs, Value};
use std::{
    rc::Rc,
    sync::{Mutex, OnceLock},
};

#[derive(Clone)]
pub struct Config {
    pub verbose: bool,
    pub debug: bool,
}

pub type DslCallback<'a> = dyn Fn(&mut CallArgs<'_>) -> Result<Value, ()> + 'a;
pub type DslFunc = Box<DslCallback<'static>>;

/// The number of arguments accepted by a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arity {
    Exact(usize),
    /// Inclusive bounds; `None` permits any count at or above `min`.
    Range {
        min: usize,
        max: Option<usize>,
    },
}

impl Arity {
    pub fn accepts(self, count: usize) -> bool {
        match self {
            Self::Exact(expected) => count == expected,
            Self::Range { min, max } => count >= min && max.is_none_or(|max| count <= max),
        }
    }
}

/// Clones share the callback, including any captured state.
#[derive(Clone)]
pub struct DslFunction {
    pub(crate) func: Rc<DslCallback<'static>>,
    pub(crate) arity: Arity,
}

impl DslFunction {
    /// A function accepting exactly `params` arguments.
    pub fn new(params: usize, func: DslFunc) -> Self {
        Self::with_arity(Arity::Exact(params), func)
    }

    /// A function accepting at least `min` arguments, with no upper limit.
    pub fn variadic(min: usize, func: DslFunc) -> Self {
        Self::with_arity(Arity::Range { min, max: None }, func)
    }

    /// A function with explicit argument bounds, including optional arguments.
    pub fn with_arity(arity: Arity, func: DslFunc) -> Self {
        Self {
            func: func.into(),
            arity,
        }
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
    use std::{cell::Cell, rc::Rc};

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
    fn call_arity_is_checked_before_invocation() {
        set_config(Config {
            verbose: false,
            debug: false,
        });
        for (arity, accepted_counts) in [
            (Arity::Exact(0), [true, false, false, false, false]),
            (Arity::Exact(2), [false, false, true, false, false]),
            (
                Arity::Range {
                    min: 0,
                    max: Some(2),
                },
                [true, true, true, false, false],
            ),
            (
                Arity::Range {
                    min: 1,
                    max: Some(2),
                },
                [false, true, true, false, false],
            ),
            (
                Arity::Range { min: 0, max: None },
                [true, true, true, true, true],
            ),
            (
                Arity::Range { min: 2, max: None },
                [false, false, true, true, true],
            ),
        ] {
            let calls = Rc::new(Cell::new(0));
            let count = calls.clone();
            let mut functions = FxHashMap::default();
            functions.insert(
                "f".into(),
                DslFunction::with_arity(
                    arity,
                    Box::new(move |args| {
                        count.set(count.get() + 1);
                        Ok(Value::Int(args.len() as i64))
                    }),
                ),
            );
            for (argc, accepted) in accepted_counts.into_iter().enumerate() {
                calls.set(0);
                let args = vec!["1"; argc].join(", ");
                let source = format!("100 + f({args})");
                assert_eq!(
                    compile_expression_validated(&source, &functions).is_ok(),
                    accepted
                );
                let result = compile_expression(&source)
                    .unwrap()
                    .execute(&NoVariables, &functions);
                assert_eq!(
                    result,
                    if accepted {
                        Ok(Value::Int(100 + argc as i64))
                    } else {
                        Err(())
                    }
                );
                assert_eq!(calls.get(), usize::from(accepted));
            }
        }
    }

    #[test]
    fn nested_calls_preserve_argument_order_and_boundaries() {
        set_config(Config {
            verbose: false,
            debug: false,
        });
        let mut functions = FxHashMap::default();
        functions.insert(
            "sum".into(),
            DslFunction::variadic(
                0,
                Box::new(|args| {
                    let mut sum = 0;
                    while !args.is_empty() {
                        sum += args.pop_int()?;
                    }
                    Ok(Value::Int(sum))
                }),
            ),
        );
        functions.insert(
            "last".into(),
            DslFunction::with_arity(
                Arity::Range {
                    min: 1,
                    max: Some(2),
                },
                Box::new(|args| args.pop()),
            ),
        );
        functions.insert(
            "overpop".into(),
            DslFunction::new(
                1,
                Box::new(|args| {
                    args.pop()?;
                    args.pop()
                }),
            ),
        );

        for (source, expected) in [
            ("sum()", 0),
            ("sum(1, sum(2, 3), 4)", 10),
            ("sum(100, last(1, 2), 3)", 105),
            ("sum(last(7), last(8, 9))", 16),
            ("sum(1, true ? sum(2, 3) : 0, 4)", 10),
        ] {
            let compiled = compile_expression_validated(source, &functions).unwrap();
            assert_eq!(
                compiled.execute(&NoVariables, &functions),
                Ok(Value::Int(expected)),
                "{source}"
            );
        }
        let compiled = compile_expression("sum(100, overpop(2))").unwrap();
        assert_eq!(compiled.execute(&NoVariables, &functions), Err(()));

        for source in ["sum(last())", "sum(missing(1))", "true || last()"] {
            assert!(
                compile_expression_validated(source, &functions).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn arguments_are_evaluated_left_to_right() {
        set_config(Config {
            verbose: false,
            debug: false,
        });
        let mut functions = FxHashMap::default();
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        functions.insert(
            "next".into(),
            DslFunction::new(
                0,
                Box::new(move |_| {
                    count.set(count.get() + 1);
                    Ok(Value::Int(count.get()))
                }),
            ),
        );
        functions.insert(
            "check".into(),
            DslFunction::variadic(
                0,
                Box::new(|args| {
                    assert_eq!(
                        args.as_slice(),
                        &[Value::Int(1), Value::Int(2), Value::Int(3)]
                    );
                    assert_eq!(args.pop_int()?, 3);
                    assert_eq!(args.as_slice(), &[Value::Int(1), Value::Int(2)]);
                    Ok(Value::Boolean(true))
                }),
            ),
        );
        let compiled =
            compile_expression_validated("check(next(), next(), next())", &functions).unwrap();
        assert_eq!(
            compiled.execute(&NoVariables, &functions),
            Ok(Value::Boolean(true))
        );
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn lists_cannot_spill_into_call_arguments() {
        set_config(Config {
            verbose: false,
            debug: false,
        });
        for source in [
            "f((1, 2))",
            "f(true ? (1, 2) : 3)",
            "f(1 + (2, 3))",
            "f(,)",
            "f(1,)",
        ] {
            assert!(compile_expression(source).is_err(), "{source}");
        }
        let mut functions = FxHashMap::default();
        functions.insert(
            "identity".into(),
            DslFunction::new(1, Box::new(|args| args.pop())),
        );
        let compiled =
            compile_expression_validated("identity(2 in (1, 2, 3))", &functions).unwrap();
        assert_eq!(
            compiled.execute(&NoVariables, &functions),
            Ok(Value::Boolean(true))
        );
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
                Box::new(|stack| {
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
                Box::new(|stack| {
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

        let call_count = Rc::new(Cell::new(0u32));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

        let cc = call_count.clone();
        functions.insert(
            "side_effect".into(),
            DslFunction::new(
                1,
                Box::new(move |stack| {
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

        let call_count = Rc::new(Cell::new(0u32));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

        let cc = call_count.clone();
        functions.insert(
            "side_effect".into(),
            DslFunction::new(
                1,
                Box::new(move |stack| {
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

        let call_count = Rc::new(Cell::new(0u32));
        let mut functions: FxHashMap<String, DslFunction> = FxHashMap::default();

        let cc = call_count.clone();
        functions.insert(
            "http".into(),
            DslFunction::new(
                1,
                Box::new(move |stack| {
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
    }
}
