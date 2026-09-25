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
mod matcher;
pub mod template;
pub mod template_executor;
pub mod template_loader;
pub mod template_string;

use std::{fmt::Write, io::Cursor, sync::Mutex, time::Duration};

use base64::{Engine, prelude::BASE64_STANDARD};
use curl::easy::Easy;
use itertools::Itertools;
use md5::{Digest, Md5};
use murmur3::murmur3_32;
use photon_dsl::{Arity, DslFunction, dsl::Value};
use rand::RngExt;
use rand::distr::{Alphabetic, Alphanumeric};
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
    /// Register a function and its underscore-free alias. Existing entries are replaced.
    pub fn add_function(&mut self, name: &str, func: DslFunction) {
        if name.contains('_') {
            self.functions.insert(name.replace('_', ""), func.clone());
        }
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

// Basic health check for outsiders to check if domain seems alive or not.
// Uses similar curl settings as `http.rs` for similar behavior
pub fn health_check(url: &str, timeout: Duration) -> Result<(), curl::Error> {
    let mut curl = Easy::new();
    curl.path_as_is(true)?;
    // TODO: maybe use useragent? for now it's just curl default for health check
    // curl.useragent(&options.user_agent).unwrap();
    // Don't verify any certs
    curl.ssl_verify_peer(false)?;
    curl.ssl_verify_host(false)?;
    curl.http_09_allowed(true)?; // Release builds run into http 0.9 not allowed errors, but dev builds not for some reason
    curl.accept_encoding("")?; // Tell CURL to accept compressed & automatically decompress body, some websites send compressed even when accept-encoding is not set.
    curl.timeout(timeout)?;
    curl.url(url)?;

    curl.perform()
}

fn init_functions() -> FxHashMap<String, DslFunction> {
    let mut context = PhotonContext {
        functions: FxHashMap::default(),
    };

    context.add_function(
        "concat",
        DslFunction::variadic(
            0,
            Box::new(|args| {
                let mut result = String::new();
                for value in args.as_slice() {
                    write!(&mut result, "{value}").map_err(|_| ())?;
                }
                Ok(Value::String(result))
            }),
        ),
    );
    for (name, all) in [("contains_all", true), ("contains_any", false)] {
        context.add_function(
            name,
            DslFunction::variadic(
                1,
                Box::new(move |args| {
                    let (haystack, needles) = args.as_slice().split_first().ok_or(())?;
                    let haystack = haystack.to_string();
                    let mut matches = needles
                        .iter()
                        .map(|needle| haystack.contains(&needle.to_string()));
                    Ok(Value::Boolean(if all {
                        matches.all(|matched| matched)
                    } else {
                        matches.any(|matched| matched)
                    }))
                }),
            ),
        );
    }

    context.add_function(
        "md5",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let inp = stack.pop()?.to_string();
                let hash = base16ct::lower::encode_string(&Md5::digest(inp));
                Ok(Value::String(hash))
            }),
        ),
    );
    context.add_function(
        "regex",
        DslFunction::new(
            2,
            Box::new(|stack| {
                let inp = stack.pop_string()?;
                let patt = stack.pop_string()?;
                let reg = Regex::new(&patt).map_err(|_| ())?; // TODO: Don't map err, use some proper DSL error handling
                Ok(Value::Boolean(reg.is_match(&inp)))
            }),
        ),
    );
    context.add_function(
        "contains",
        DslFunction::new(
            2,
            Box::new(|stack| {
                let needle = stack.pop_string()?;
                let haystack = stack.pop_string()?;
                Ok(Value::Boolean(haystack.contains(&needle)))
            }),
        ),
    );
    context.add_function(
        "starts_with",
        DslFunction::variadic(
            2,
            Box::new(|args| {
                let (value, prefixes) = args.as_slice().split_first().ok_or(())?;
                let value = value.to_string();
                Ok(Value::Boolean(
                    prefixes
                        .iter()
                        .any(|prefix| value.starts_with(&prefix.to_string())),
                ))
            }),
        ),
    );
    context.add_function(
        "to_lower",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let inp = stack.pop_string()?;
                Ok(Value::String(inp.to_lowercase()))
            }),
        ),
    );
    context.add_function(
        "to_upper",
        DslFunction::new(
            1,
            Box::new(|args| Ok(Value::String(args.pop_string()?.to_uppercase()))),
        ),
    );
    context.add_function(
        "len",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let inp = stack.pop_string()?;
                Ok(Value::Int(inp.len() as i64))
            }),
        ),
    );
    context.add_function(
        "url_encode",
        DslFunction::with_arity(
            Arity::Range {
                min: 1,
                max: Some(2),
            },
            Box::new(|args| {
                let args = args.as_slice();
                let encode_all = matches!(
                    args.get(1),
                    Some(Value::Boolean(true) | Value::Int(1) | Value::Short(1))
                );
                let input = args[0].to_string();
                let mut result = String::with_capacity(input.len());
                for byte in input.bytes() {
                    // Nuclei preserves these special characters unless explicitly requested.
                    let unescaped = byte.is_ascii_alphanumeric()
                        || (!encode_all
                            && matches!(
                                byte,
                                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
                            ));
                    if unescaped {
                        result.push(char::from(byte));
                    } else {
                        write!(&mut result, "%{byte:02X}").map_err(|_| ())?;
                    }
                }
                Ok(Value::String(result))
            }),
        ),
    );
    context.add_function(
        "hex_decode",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let inp = stack.pop_string()?;
                let decoded_vec = base16ct::mixed::decode_vec(inp).map_err(|_| ())?; // TODO: Don't map err, use some proper DSL error handling
                let decoded_str = String::from_utf8_lossy(&decoded_vec);
                Ok(Value::String(String::from(decoded_str)))
            }),
        ),
    );
    context.add_function(
        "base64_decode",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let inp = stack.pop_string()?;
                let decoded_vec = BASE64_STANDARD.decode(inp).map_err(|_| ())?; // TODO: Don't map err, use some proper DSL error handling

                // TODO: possibly needs to return raw bytes (not supported in DSL right now) instead of valid UTF-8
                match String::from_utf8(decoded_vec) {
                    Ok(decoded_str) => Ok(Value::String(decoded_str)),
                    Err(_) => Err(()),
                }
            }),
        ),
    );
    context.add_function(
        "base64",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let inp = stack.pop_string()?;
                Ok(Value::String(BASE64_STANDARD.encode(inp)))
            }),
        ),
    );
    context.add_function(
        "base64_py",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let inp = stack.pop_string()?;
                let encoded = BASE64_STANDARD.encode(inp);
                let mut pythonic = String::with_capacity(encoded.len() + 10); // Slightly larger string, to account for the added spaces in most cases

                // According to nuclei, Python's base64 encoder creates base64 with lines of max length 76
                // Although I haven't been able to verify that, might be old python behavior?
                for chunk in &encoded.chars().chunks(76) {
                    let mut len = 0;
                    for chr in chunk {
                        pythonic.push(chr);
                        len += 1;
                    }
                    if len == 76 {
                        pythonic.push('\n');
                    }
                }

                Ok(Value::String(pythonic))
            }),
        ),
    );
    context.add_function(
        "mmh3", // MurMurHash3
        DslFunction::new(
            1,
            Box::new(|stack| {
                let inp = stack.pop_string()?;
                let hash_result = murmur3_32(&mut Cursor::new(inp), 0).map_err(|_| ())?;
                Ok(Value::Int(hash_result as i64))
            }),
        ),
    );
    context.add_function(
        "rand_int",
        DslFunction::new(
            2,
            Box::new(|stack| {
                let max = stack.pop_int()?;
                let min = stack.pop_int()?;

                // [min, max) like nuclei does, exclusive range
                let mut rng = rand::rng();
                let rand_value = rng.random_range(min..max);

                Ok(Value::Int(rand_value))
            }),
        ),
    );
    context.add_function(
        "to_number",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let num = stack.pop()?;

                match num {
                    Value::String(num_str) => {
                        Ok(Value::Int(num_str.parse::<i64>().map_err(|_| ())?))
                    }
                    Value::Int(num) => Ok(Value::Int(num)),
                    _ => Err(()),
                }
            }),
        ),
    );
    context.add_function(
        "rand_base",
        DslFunction::with_arity(
            Arity::Range {
                min: 1,
                max: Some(3),
            },
            Box::new(|args| {
                let args = args.as_slice();
                let length = args[0]
                    .to_string()
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ())?;
                // Nuclei accepts three arguments but only uses the charset with two.
                let custom = (args.len() == 2).then(|| args[1].to_string());
                let charset = custom
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
                    .as_bytes();
                let mut rng = rand::rng();
                // Nuclei's RandSeq samples UTF-8 bytes and converts each byte to a rune.
                let result = (0..length)
                    .map(|_| char::from(charset[rng.random_range(0..charset.len())]))
                    .collect();
                Ok(Value::String(result))
            }),
        ),
    );
    context.add_function(
        "rand_text_numeric",
        DslFunction::with_arity(
            Arity::Range {
                min: 1,
                max: Some(2),
            },
            Box::new(|args| {
                let args = args.as_slice();
                let length = args[0]
                    .to_string()
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ())?;
                let mut digits = b"0123456789".to_vec();
                if args.len() == 2 {
                    let excluded = args[1].to_string();
                    digits.retain(|digit| !excluded.as_bytes().contains(digit));
                }
                if digits.is_empty() && length > 0 {
                    return Err(());
                }
                let mut rng = rand::rng();
                let result = (0..length)
                    .map(|_| char::from(digits[rng.random_range(0..digits.len())]))
                    .collect();
                Ok(Value::String(result))
            }),
        ),
    );
    context.add_function(
        "rand_text_alphanumeric",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let count = stack.pop_int()?;

                let rng = rand::rng();
                let rand_value = rng
                    .sample_iter(&Alphanumeric)
                    .take(count as usize)
                    .map(char::from);

                Ok(Value::String(rand_value.collect()))
            }),
        ),
    );
    context.add_function(
        "rand_text_alpha",
        DslFunction::new(
            1,
            Box::new(|stack| {
                let count = stack.pop_int()?;

                let rng = rand::rng();
                let rand_value = rng
                    .sample_iter(&Alphabetic)
                    .take(count as usize)
                    .map(char::from);

                Ok(Value::String(rand_value.collect()))
            }),
        ),
    );

    context.functions
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

        let res = compiled.unwrap().execute(&NoVariables, fns);
        assert!(res.is_ok());
        res.unwrap() == Value::Boolean(true)
    }

    #[test]
    fn automatic_function_aliases() {
        photon_dsl::set_config(photon_dsl::Config {
            verbose: false,
            debug: false,
        });
        let functions = init_functions();
        for name in functions.keys().filter(|name| name.contains('_')) {
            assert!(functions.contains_key(&name.replace('_', "")), "{name}");
        }
        for source in [
            "toupper('Hello') == to_upper('Hello')",
            "tolower('Hello') == to_lower('Hello')",
            "startswith('Hello', 'Hi', 'Hello')",
            "containsall('abc', 'a', 'b') && containsany('abc', 'z', 'c')",
            "hexdecode('4142') == 'AB'",
            "base64decode(base64('test')) == 'test'",
            "randbase(3, 'x') == 'xxx'",
            "randtextnumeric(3, '123456789') == '000'",
        ] {
            let compiled =
                photon_dsl::parser::compile_expression_validated(source, &functions).unwrap();
            assert_eq!(
                compiled.execute(&NoVariables, &functions),
                Ok(Value::Boolean(true)),
                "{source}"
            );
        }
        for source in ["toupper()", "startswith('Hello')", "randbase(1, 2, 3, 4)"] {
            assert!(
                photon_dsl::parser::compile_expression_validated(source, &functions).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn custom_aliases_share_state_and_are_replaced_together() {
        photon_dsl::set_config(photon_dsl::Config {
            verbose: false,
            debug: false,
        });
        let mut context = PhotonContext {
            functions: init_functions(),
        };
        let counter = std::cell::Cell::new(0);
        context.add_function(
            "call_count",
            DslFunction::new(
                0,
                Box::new(move |_| {
                    counter.set(counter.get() + 1);
                    Ok(Value::Int(counter.get()))
                }),
            ),
        );
        assert!(test_expression(
            &context.functions,
            "call_count() == 1 && callcount() == 2"
        ));

        context.add_function(
            "call_count",
            DslFunction::new(1, Box::new(|args| args.pop())),
        );
        assert!(test_expression(
            &context.functions,
            "call_count(7) == 7 && callcount(8) == 8"
        ));
        for source in ["call_count()", "callcount()"] {
            assert!(
                photon_dsl::parser::compile_expression_validated(source, &context.functions)
                    .is_err()
            );
        }
    }

    #[test]
    fn variadic_functions() {
        photon_dsl::set_config(photon_dsl::Config {
            verbose: false,
            debug: false,
        });
        let functions = init_functions();
        for source in [
            "concat() == ''",
            "concat('a') == 'a'",
            "concat('a', 2, true, concat('b', 'c')) == 'a2truebc'",
            "contains('prefixabc', concat('a', 'b', 'c'))",
            "contains_all('abc', 'a', 'bc')",
            "!contains_all('abc', 'z', 'a')",
            "contains_any('abc', 'a', 'z')",
            "!contains_any('abc', 'x', 'z')",
            "contains_all('abc')",
            "!contains_any('abc')",
            "contains_all(123, 1, 23)",
            "contains_any(123, false, 2)",
            "concat('prefix', contains_any('abc', 'a', 'z'), 'suffix') == 'prefixtruesuffix'",
        ] {
            assert!(test_expression(&functions, source), "{source}");
        }
        for source in ["contains_all()", "contains_any()"] {
            assert!(photon_dsl::parser::compile_expression_validated(source, &functions).is_err());
            assert!(
                compile_expression(source)
                    .unwrap()
                    .execute(&NoVariables, &functions)
                    .is_err()
            );
        }
    }

    #[test]
    fn rand_base() {
        photon_dsl::set_config(photon_dsl::Config {
            verbose: false,
            debug: false,
        });
        let functions = init_functions();
        let alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (source, length, charset) in [
            ("rand_base(12)", 12, alphanumeric),
            ("rand_base(0)", 0, alphanumeric),
            ("rand_base(' 12 ')", 12, alphanumeric),
            ("rand_base(32, '')", 32, alphanumeric),
            ("rand_base(32, ' \t\n')", 32, alphanumeric),
            ("rand_base(32, 'abc123')", 32, "abc123"),
            ("rand_base(12, 'x')", 12, "x"),
            ("rand_base(12, 7)", 12, "7"),
            ("rand_base(12, true)", 12, "true"),
            ("rand_base(12, 'é')", 12, "Ã©"),
            ("rand_base(32, '#', 'ignored')", 32, alphanumeric),
        ] {
            let compiled =
                photon_dsl::parser::compile_expression_validated(source, &functions).unwrap();
            let Value::String(result) = compiled.execute(&NoVariables, &functions).unwrap() else {
                panic!("{source} should return a string");
            };
            assert_eq!(result.chars().count(), length, "{source}");
            assert!(
                result.chars().all(|c| charset.contains(c)),
                "{source}: {result}"
            );
        }
        assert!(test_expression(
            &functions,
            "concat('prefix', rand_base(3, 'x'), 'suffix') == 'prefixxxxsuffix'"
        ));

        for source in ["rand_base()", "rand_base(1, 'x', 'y', 'z')"] {
            assert!(photon_dsl::parser::compile_expression_validated(source, &functions).is_err());
            assert!(
                compile_expression(source)
                    .unwrap()
                    .execute(&NoVariables, &functions)
                    .is_err()
            );
        }
        for source in [
            "rand_base(-1)",
            "rand_base('invalid')",
            "rand_base(true)",
            "rand_base('18446744073709551616')",
        ] {
            let compiled =
                photon_dsl::parser::compile_expression_validated(source, &functions).unwrap();
            assert!(
                compiled.execute(&NoVariables, &functions).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn rand_text_numeric() {
        photon_dsl::set_config(photon_dsl::Config {
            verbose: false,
            debug: false,
        });
        let functions = init_functions();
        for source in [
            "regex('^[0-9]{32}$', rand_text_numeric(32))",
            "regex('^[2-9]{32}$', rand_text_numeric(32, '01'))",
            "regex('^[0-9]{12}$', rand_text_numeric(' 12 ', ''))",
            "rand_text_numeric(5, '123456789') == '00000'",
            "rand_text_numeric(5, '012345678') == '99999'",
            "rand_text_numeric(0) == ''",
            "rand_text_numeric(0, '0123456789') == ''",
            "concat('prefix', rand_text_numeric(3, 123456789), 'suffix') == 'prefix000suffix'",
        ] {
            assert!(test_expression(&functions, source), "{source}");
            assert!(photon_dsl::parser::compile_expression_validated(source, &functions).is_ok());
        }
        for source in ["rand_text_numeric()", "rand_text_numeric(1, '0', '1')"] {
            assert!(photon_dsl::parser::compile_expression_validated(source, &functions).is_err());
            assert!(
                compile_expression(source)
                    .unwrap()
                    .execute(&NoVariables, &functions)
                    .is_err()
            );
        }
        for source in [
            "rand_text_numeric(-1)",
            "rand_text_numeric('invalid')",
            "rand_text_numeric(true)",
            "rand_text_numeric(1, '0123456789')",
        ] {
            let compiled =
                photon_dsl::parser::compile_expression_validated(source, &functions).unwrap();
            assert!(
                compiled.execute(&NoVariables, &functions).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn url_encoding_matches_nuclei() {
        photon_dsl::set_config(photon_dsl::Config {
            verbose: false,
            debug: false,
        });
        let functions = init_functions();
        for (source, expected) in [
            ("url_encode('')", ""),
            (
                "url_encode('Hello world+/%?&=:#')",
                "Hello%20world%2B%2F%25%3F%26%3D%3A%23",
            ),
            (r#"url_encode("-_.!~*'()")"#, "-_.!~*'()"),
            (
                r#"url_encode("AZaz09-_.!~*'()", true)"#,
                "AZaz09%2D%5F%2E%21%7E%2A%27%28%29",
            ),
            ("url_encode('a_b', false)", "a_b"),
            ("url_encode('a_b', 1)", "a%5Fb"),
            ("url_encode('a_b', 0)", "a_b"),
            ("url_encode('a_b', 'true')", "a_b"),
            ("url_encode('é😀')", "%C3%A9%F0%9F%98%80"),
            ("url_encode(123)", "123"),
            ("urlencode('a b')", "a%20b"),
            (
                "concat('prefix', url_encode('a b'), 'suffix')",
                "prefixa%20bsuffix",
            ),
        ] {
            let compiled =
                photon_dsl::parser::compile_expression_validated(source, &functions).unwrap();
            assert_eq!(
                compiled.execute(&NoVariables, &functions),
                Ok(Value::String(expected.into())),
                "{source}"
            );
        }
        for source in ["url_encode()", "url_encode('a', true, false)"] {
            assert!(photon_dsl::parser::compile_expression_validated(source, &functions).is_err());
            assert!(
                compile_expression(source)
                    .unwrap()
                    .execute(&NoVariables, &functions)
                    .is_err()
            );
        }
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
        assert!(test_expression(
            &functions,
            "base64('base64 test string') == 'YmFzZTY0IHRlc3Qgc3RyaW5n'"
        ));
        // Line shorter than 76 letters case
        assert!(test_expression(
            &functions,
            "base64_py('base64 test string') == 'YmFzZTY0IHRlc3Qgc3RyaW5n'"
        ));
        // Line longer than 76 letters case
        assert!(test_expression(
            &functions,
            "base64_py('base64 test string base64 test string base64 test string base64 test string base64 test string') == 'YmFzZTY0IHRlc3Qgc3RyaW5nIGJhc2U2NCB0ZXN0IHN0cmluZyBiYXNlNjQgdGVzdCBzdHJpbmcg\nYmFzZTY0IHRlc3Qgc3RyaW5nIGJhc2U2NCB0ZXN0IHN0cmluZw=='"
        ));
        // Random tests, shows that rand_int is exclusive
        assert!(test_expression(&functions, "rand_int(1, 3) >= 1"));
        assert!(test_expression(&functions, "rand_int(1, 3) < 3"));
    }
}
