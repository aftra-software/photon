use std::{cell::RefCell, rc::Rc};

use photon_dsl::dsl::{Bytecode, CompiledExpression, DSLStack, OPCode, Value, VariableContainer};
use rustc_hash::FxHashSet;

use crate::{
    cache::{Cache, RegexCache},
    get_config,
    http::{get_bracket_pattern, CurlHandle},
    template::{Context, MatchResult, Template},
    template_executor::ExecutionOptions,
    PhotonContext,
};

fn handle_flow_op(op: OPCode, stack: &mut DSLStack) -> Result<(), ()> {
    match op {
        OPCode::LoadConstBoolTrue => {
            stack.push(Value::Boolean(true));
            Ok(())
        }
        OPCode::LoadConstBoolFalse => {
            stack.push(Value::Boolean(false));
            Ok(())
        }
        OPCode::Add => {
            let b = stack.pop()?;
            match b {
                Value::Int(b) => {
                    let a = stack.pop_int()?;
                    stack.push(Value::Int(a + b));
                    Ok(())
                }
                Value::String(b) => {
                    let a = stack.pop_string()?;
                    stack.push(Value::String(format!("{a}{b}")));
                    Ok(())
                }
                _ => Err(()),
            }
        }
        OPCode::Mul => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Int(a * b));
            Ok(())
        }
        OPCode::Div => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Int(a / b));
            Ok(())
        }
        OPCode::CmpEq => {
            let b = stack.pop()?;
            let a = stack.pop()?;
            stack.push(Value::Boolean(a == b));
            Ok(())
        }
        OPCode::Exp => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Int(a.pow(b as u32)));
            Ok(())
        }
        OPCode::CmpNeq => {
            let b = stack.pop()?;
            let a = stack.pop()?;
            stack.push(Value::Boolean(a != b));
            Ok(())
        }
        OPCode::CmpGt => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Boolean(a > b));
            Ok(())
        }
        OPCode::CmpGtEq => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Boolean(a >= b));
            Ok(())
        }
        OPCode::CmpLt => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Boolean(a < b));
            Ok(())
        }
        OPCode::CmpLtEq => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Boolean(a <= b));
            Ok(())
        }
        OPCode::RegEq => {
            let b = stack.pop_string()?;
            let a = stack.pop_string()?;
            let matched = Regex::new(&b).map_err(|_| ())?.is_match(&a);
            stack.push(Value::Boolean(matched));
            Ok(())
        }
        OPCode::RegNeq => {
            let b = stack.pop_string()?;
            let a = stack.pop_string()?;
            let matched = Regex::new(&b).map_err(|_| ())?.is_match(&a);
            stack.push(Value::Boolean(!matched));
            Ok(())
        }
        OPCode::And => {
            let b = stack.pop_bool()?;
            let a = stack.pop_bool()?;
            stack.push(Value::Boolean(a && b));
            Ok(())
        }
        OPCode::Or => {
            let b = stack.pop_bool()?;
            let a = stack.pop_bool()?;
            stack.push(Value::Boolean(a || b));
            Ok(())
        }
        OPCode::Invert => {
            let val = stack.pop()?;
            match val {
                Value::Int(i) => {
                    stack.push(Value::Int(-i));
                    Ok(())
                }
                Value::Boolean(b) => {
                    stack.push(Value::Boolean(!b));
                    Ok(())
                }
                _ => Err(()),
            }
        }
        OPCode::In => {
            let len = stack.pop_short()?;
            let mut haystack = Vec::new();
            for _ in 0..len {
                haystack.push(stack.pop()?);
            }
            let needle = stack.pop()?;
            stack.push(Value::Boolean(haystack.contains(&needle)));
            Ok(())
        }
        _ => todo!("TODO: implement OP {:?}", op),
    }
}

/// Represents a parsed flow expression from a template's `flow:` field.
///
/// Photon supports three flow categories:
/// - Category 1: Simple boolean chains (e.g., `http(1) && http(2)`)
/// - Category 2: Iterate loops (e.g., `http(1) for (let x of iterate(template["key"])) { set("x", x); http(2); }`)
/// - Unsupported: Complex flows that don't match categories 1 or 2 (will be gracefully skipped)
#[derive(Debug, Clone)]
pub enum FlowExpression {
    /// Category 1: Simple boolean chains with `http(N)` calls and boolean operators (`&&`, `||`)
    BooleanChain(CompiledExpression),

    /// Category 2: Iterate loop pattern
    IterateLoop {
        /// 0-indexed request to execute first (extracts data for iteration)
        init_request: usize,
        /// Variable name to set in each iteration via `set("name", value)`
        var_name: String,
        /// Extractor key to iterate over from template context
        source_key: String,
        /// 0-indexed request to execute in each iteration
        loop_request: usize,
    },

    /// Unsupported: Complex flows that don't match categories 1 or 2
    /// These templates will be skipped with a debug log message
    Unsupported(String),
}

pub fn execute_iterate_flow<K, C>(
    template: &Template,
    iterate_loop: &IterateLoop,
    base_url: &str,
    options: &ExecutionOptions,
    curl: &mut CurlHandle,
    regex_cache: &RegexCache,
    ctx: Rc<RefCell<Context>>,
    photon_ctx: &PhotonContext,
    req_counter: &mut u32,
    cache: &mut Cache,
    callback: &Option<K>,
    continue_predicate: &Option<C>,
) -> bool
where
    K: Fn(&Template, &MatchResult),
    C: Fn() -> bool,
{
    let Some(init_http) = template.http.get(iterate_loop.init_request) else {
        return true;
    };

    if continue_predicate.is_some() && !continue_predicate.as_ref().unwrap()() {
        return false;
    }

    let match_results: FxHashSet<MatchResult> = init_http.execute(
        base_url,
        options,
        curl,
        regex_cache,
        ctx.clone(),
        photon_ctx,
        req_counter,
        cache,
    );
    for matched in &match_results {
        if !matched.internal {
            if let Some(callback) = callback {
                callback(template, matched)
            }
        }
    }

    let source_value = ctx.borrow().get(&iterate_loop.source_key);
    let values: Vec<Value> = match source_value {
        None => vec![],
        Some(Value::String(val)) => {
            if val.contains(',') {
                val.split(',')
                    .map(|part| part.trim())
                    .filter(|part| !part.is_empty())
                    .map(|part| Value::String(part.to_string()))
                    .collect()
            } else if val.trim().is_empty() {
                vec![]
            } else {
                vec![Value::String(val)]
            }
        }
        Some(Value::Int(value)) => vec![Value::String(value.to_string())],
        Some(Value::Short(value)) => vec![Value::String(value.to_string())],
        Some(Value::Boolean(value)) => vec![Value::String(value.to_string())],
    };

    let Some(loop_http) = template.http.get(iterate_loop.loop_request) else {
        return true;
    };

    for value in values {
        ctx.borrow_mut().insert(&iterate_loop.var_name, value);
        if continue_predicate.is_some() && !continue_predicate.as_ref().unwrap()() {
            return false;
        }
        let match_results: FxHashSet<MatchResult> = loop_http.execute(
            base_url,
            options,
            curl,
            regex_cache,
            ctx.clone(),
            photon_ctx,
            req_counter,
            cache,
        );
        for matched in &match_results {
            if !matched.internal {
                if let Some(callback) = callback {
                    callback(template, matched)
                }
            }
        }
    }

    true
}

pub fn execute_flow_bytecodes<K, C>(
    template: &Template,
    compiled: &CompiledExpression,
    base_url: &str,
    options: &ExecutionOptions,
    curl: &mut CurlHandle,
    regex_cache: &RegexCache,
    ctx: Rc<RefCell<Context>>,
    photon_ctx: &PhotonContext,
    req_counter: &mut u32,
    cache: &mut Cache,
    callback: &Option<K>,
    continue_predicate: &Option<C>,
) -> bool
where
    K: Fn(&Template, &MatchResult),
    C: Fn() -> bool,
{
    let mut stack = DSLStack::new();
    let bytecode = compiled.bytecode();

    let mut ptr = 0;
    while ptr < bytecode.len() {
        match &bytecode[ptr] {
            Bytecode::Instr(OPCode::CallFunc) => {
                ptr += 1;
                if let Bytecode::Value(Value::String(key)) = &bytecode[ptr] {
                    if key == "http" {
                        let n = match stack.pop() {
                            Ok(Value::Int(i)) => i as usize,
                            Ok(Value::Short(s)) => s as usize,
                            _ => {
                                stack.push(Value::Boolean(false));
                                continue;
                            }
                        };

                        if n < 1 || n > template.http.len() {
                            stack.push(Value::Boolean(false));
                            continue;
                        }

                        if let Some(pred) = continue_predicate {
                            if !pred() {
                                return false;
                            }
                        }

                        let match_results: FxHashSet<MatchResult> = template.http[n - 1].execute(
                            base_url,
                            options,
                            curl,
                            regex_cache,
                            ctx.clone(),
                            photon_ctx,
                            req_counter,
                            cache,
                        );

                        for matched in &match_results {
                            if !matched.internal {
                                if let Some(cb) = callback {
                                    cb(template, matched);
                                }
                            }
                        }

                        stack.push(Value::Boolean(!match_results.is_empty()));
                    } else {
                        let stack_len = stack.len();
                        let (params, ret) = match photon_ctx.execute_function(&key, &mut stack) {
                            Ok(result) => result,
                            Err(_) => {
                                debug!("Function not found: {:?}", key);
                                return false;
                            }
                        };
                        if stack.len() != stack_len - params {
                            debug!(
                                "Function {} popped {} values off the stack, expected {} popped.",
                                key,
                                stack_len - stack.len(),
                                params
                            );
                            return false;
                        }
                        stack.push(ret);
                    }
                } else {
                    debug!("LoadVar called with invalid argument: {:?}", &bytecode[ptr]);
                    return false;
                }
            }
            Bytecode::Instr(OPCode::LoadVar) => {
                ptr += 1;
                if let Bytecode::Value(Value::String(key)) = &bytecode[ptr] {
                    if !ctx.borrow().contains_key(&key) {
                        debug!("Variable not found: {:?}", key);
                        return false;
                    }
                    stack.push(ctx.borrow().get(&key).unwrap());
                } else {
                    debug!("LoadVar called with invalid argument: {:?}", &bytecode[ptr]);
                    return false;
                }
            }
            Bytecode::Instr(OPCode::LoadConstInt) => {
                ptr += 1;
                if let Bytecode::Value(Value::Int(val)) = &bytecode[ptr] {
                    stack.push(Value::Int(*val));
                } else {
                    debug!(
                        "LoadConstInt called with invalid argument: {:?}",
                        &bytecode[ptr]
                    );
                    return false;
                }
            }
            Bytecode::Instr(OPCode::LoadConstShort) => {
                ptr += 1;
                if let Bytecode::Value(Value::Short(val)) = &bytecode[ptr] {
                    stack.push(Value::Short(*val));
                } else {
                    debug!(
                        "LoadConstInt called with invalid argument: {:?}",
                        &bytecode[ptr]
                    );
                    return false;
                }
            }
            Bytecode::Instr(OPCode::ShortJump) => {
                ptr += 1;
                let should_jump = match stack.pop_bool() {
                    Ok(value) => value,
                    Err(_) => return false,
                };
                if should_jump {
                    if let Bytecode::Value(Value::Short(val)) = &bytecode[ptr] {
                        ptr = (ptr as isize + *val as isize) as usize;
                    } else {
                        debug!(
                            "ShortJump called with invalid argument: {:?}",
                            &bytecode[ptr]
                        );
                        return false;
                    }
                }
            }
            Bytecode::Instr(OPCode::LoadConstStr) => {
                ptr += 1;
                if let Bytecode::Value(Value::String(val)) = &bytecode[ptr] {
                    let mut baked = val.clone();
                    loop {
                        let mut changed = false;
                        let tmp = baked.clone();
                        let matches: Vec<_> =
                            get_bracket_pattern().captures_iter(tmp.as_str()).collect();

                        for mat in matches.iter() {
                            let match_str = mat.get(1).unwrap().as_str();
                            if let Some(matched) = ctx.borrow().get(match_str) {
                                baked.replace_range(
                                    mat.get(0).unwrap().range(),
                                    &matched.to_string(),
                                );
                                changed = true;
                                break;
                            }
                        }
                        if !changed {
                            break;
                        }
                    }
                    stack.push(Value::String(baked));
                } else {
                    debug!(
                        "LoadConstStr called with invalid argument: {:?}",
                        &bytecode[ptr]
                    );
                    return false;
                }
            }
            Bytecode::Instr(op) => {
                let res = handle_flow_op(*op, &mut stack);
                if let Err(_) = res {
                    return false;
                }
            }
            Bytecode::Value(_) => {
                debug!("Unexpected value while executing bytecode");
                return false;
            }
        }
        ptr += 1;
    }

    match stack.pop_bool() {
        Ok(value) => value,
        Err(_) => false,
    }
}

use regex::Regex;

/// Parsed components of a Category 2 iterate loop flow pattern.
///
/// Represents the simple iterate pattern:
/// ```text
/// http(N)
/// for (let VAR of iterate(template["KEY"])) {
///   set("VAR2", VAR);
///   http(M);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct IterateLoop {
    /// 0-indexed request to execute first (extracts data for iteration)
    pub init_request: usize,
    /// Variable name set in each iteration via set("name", value)
    pub var_name: String,
    /// Extractor key to iterate over from template context
    pub source_key: String,
    /// 0-indexed request to execute in each iteration
    pub loop_request: usize,
}

/// Parse a flow string to extract a simple Category 2 iterate loop pattern.
///
/// Matches the canonical nuclei iterate pattern:
/// - `http(N)` followed by a single `for (let VAR of iterate(template["KEY"])) { set("VAR2", VAR); http(M); }`
/// - Handles `template["KEY"]`, `template['KEY']`, and `template.KEY` notation
/// - Handles optional semicolons and whitespace variations
/// - Converts 1-indexed http() calls to 0-indexed
///
/// Returns `None` if the string doesn't match the simple iterate pattern.
pub fn parse_iterate_pattern(flow_str: &str) -> Option<IterateLoop> {
    // Rust's regex crate does NOT support backreferences, so we use explicit
    // alternations for bracket notation with double quotes, single quotes, and dot notation.
    //
    // Capture groups:
    //   1 = init request number (1-indexed)
    //   2 = loop variable name
    //   3 = key via bracket double-quote: template["KEY"]
    //   4 = key via bracket single-quote: template['KEY']
    //   5 = key via dot notation: template.KEY
    //   6 = var_name from set() call
    //   7 = loop request number (1-indexed)
    let re = Regex::new(
        r#"(?s)^\s*http\((\d+)\)\s*;?\s*for\s*\(\s*let\s+(\w+)\s+of\s+iterate\(template(?:\[\"(\w+)\"\]|\['(\w+)'\]|\.(\w+))\)\)\s*\{\s*set\(\s*["'](\w+)["']\s*,\s*\w+\s*\);?\s*http\((\d+)\)\s*;?\s*\}\s*$"#
    ).ok()?;
    let caps = re.captures(flow_str)?;
    let init_request_1indexed: usize = caps.get(1)?.as_str().parse().ok()?;
    // cap 2 = loop variable (e.g. "item"), used for structure validation
    let source_key = caps
        .get(3)
        .or_else(|| caps.get(4))
        .or_else(|| caps.get(5))?
        .as_str()
        .to_string();
    let var_name = caps.get(6)?.as_str().to_string();
    let loop_request_1indexed: usize = caps.get(7)?.as_str().parse().ok()?;
    let init_request = init_request_1indexed.checked_sub(1)?;
    let loop_request = loop_request_1indexed.checked_sub(1)?;
    Some(IterateLoop {
        init_request,
        var_name,
        source_key,
        loop_request,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        env, fs, process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use curl::easy::Easy2;
    use rustc_hash::FxHashMap;

    use crate::{
        cache::{Cache, CacheKey, RegexCache},
        http::{Collector, HttpReq, HttpResponse},
        matcher::{Extractor, ExtractorPart, ExtractorType, Matcher, MatcherType, ResponsePart},
        template::{
            AttackMode, Condition, Context, ContextScope, HttpRequest, Info, MatchResult, Method,
            Severity, Template,
        },
        template_executor::ExecutionOptions,
        template_loader::{load_template, TemplateError},
    };
    use photon_dsl::parser::compile_expression;

    fn build_info() -> Info {
        Info {
            name: String::new(),
            author: vec![],
            description: String::new(),
            remediation: None,
            classification: None,
            severity: Severity::Info,
            reference: vec![],
            tags: vec![],
        }
    }

    fn build_status_matcher() -> Matcher {
        Matcher {
            r#type: MatcherType::Status(vec![200]),
            name: None,
            negative: false,
            group: None,
            internal: false,
            part: ResponsePart::Body,
            condition: Condition::OR,
        }
    }

    fn build_http_request(path: &str, extractors: Vec<Extractor>) -> HttpRequest {
        HttpRequest {
            extractors,
            matchers: vec![build_status_matcher()],
            payloads: vec![],
            attack_mode: AttackMode::Batteringram,
            matchers_condition: Condition::OR,
            path: vec![HttpReq {
                method: Method::GET,
                headers: vec![],
                path: path.to_string(),
                body: String::new(),
                raw: String::new(),
                follow_redirects: false,
                max_redirects: None,
            }],
        }
    }

    fn build_template(http: Vec<HttpRequest>) -> Template {
        Template {
            id: String::from("test"),
            info: build_info(),
            http,
            variables: vec![],
            dsl_variables: vec![],
            flow: None,
        }
    }

    fn store_response(cache: &mut Cache, url: &str, status_code: u32) {
        cache.store(
            &CacheKey(Method::GET, vec![], url.to_string()),
            Some(HttpResponse {
                req_url: url.to_string(),
                body: vec![],
                headers: vec![],
                status_code,
                duration: 0.1,
            }),
        );
    }

    fn build_iterate_context() -> Rc<RefCell<Context>> {
        Rc::from(RefCell::from(Context {
            variables: FxHashMap::default(),
            parent: None,
            scope: ContextScope::Template,
        }))
    }

    fn build_photon_context() -> PhotonContext {
        PhotonContext {
            functions: crate::init_functions(),
        }
    }

    fn build_global_context() -> Rc<RefCell<Context>> {
        Rc::from(RefCell::from(Context {
            variables: FxHashMap::default(),
            parent: None,
            scope: ContextScope::Global,
        }))
    }

    fn load_template_from_yaml(yaml: &str) -> Result<Template, TemplateError> {
        let mut path = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let filename = format!("photon-flow-test-{}-{}.yaml", process::id(), nanos);
        path.push(filename);
        fs::write(&path, yaml).expect("failed to write temp template");
        let mut regex_cache = RegexCache::new();
        let result = load_template(path.to_str().unwrap(), &mut regex_cache);
        let _ = fs::remove_file(&path);
        result
    }

    #[test]
    fn test_parse_canonical_bracket_double_quotes() {
        // Real pattern from CVE-2023-6970.yaml
        let flow = r#"http(1);
  for (let recipe of iterate(template["recipe_ids"])) {
    set("recipe_id", recipe);
    http(2);
  }"#;
        let result = parse_iterate_pattern(flow).unwrap();
        assert_eq!(result.init_request, 0);
        assert_eq!(result.source_key, "recipe_ids");
        assert_eq!(result.var_name, "recipe_id");
        assert_eq!(result.loop_request, 1);
    }

    #[test]
    fn test_parse_dot_notation_no_semicolons() {
        // Real pattern from CVE-2024-45309.yaml
        let flow = r#"http(1)
  for (let projectName of iterate(template.project)) {
    set("project", projectName)
    http(2)
  }"#;
        let result = parse_iterate_pattern(flow).unwrap();
        assert_eq!(result.init_request, 0);
        assert_eq!(result.source_key, "project");
        assert_eq!(result.var_name, "project");
        assert_eq!(result.loop_request, 1);
    }

    #[test]
    fn test_parse_dot_notation_underscore_key() {
        // Real pattern from CVE-2020-13125.yaml
        let flow = r#"http(1)
  for (let widget_id of iterate(template.widgets_id)) {
    set("widget_id", widget_id)
    http(2)
  }"#;
        let result = parse_iterate_pattern(flow).unwrap();
        assert_eq!(result.init_request, 0);
        assert_eq!(result.source_key, "widgets_id");
        assert_eq!(result.var_name, "widget_id");
        assert_eq!(result.loop_request, 1);
    }

    #[test]
    fn test_parse_no_space_after_for() {
        // Real pattern from iterate-one-value-flow.yaml (nuclei integration test)
        let flow = r#"http(1)
  for(let value of iterate(template.extracted)){
    set("value", value)
    http(2)
  }"#;
        let result = parse_iterate_pattern(flow).unwrap();
        assert_eq!(result.init_request, 0);
        assert_eq!(result.source_key, "extracted");
        assert_eq!(result.var_name, "value");
        assert_eq!(result.loop_request, 1);
    }

    #[test]
    fn test_parse_single_quotes_bracket() {
        let flow =
            "http(1)\nfor (let x of iterate(template['items'])) {\n  set('val', x);\n  http(3);\n}";
        let result = parse_iterate_pattern(flow).unwrap();
        assert_eq!(result.init_request, 0);
        assert_eq!(result.source_key, "items");
        assert_eq!(result.var_name, "val");
        assert_eq!(result.loop_request, 2);
    }

    #[test]
    fn test_parse_higher_request_numbers() {
        let flow =
            "http(3)\nfor (let v of iterate(template.data)) {\n  set(\"v\", v)\n  http(5)\n}";
        let result = parse_iterate_pattern(flow).unwrap();
        assert_eq!(result.init_request, 2);
        assert_eq!(result.source_key, "data");
        assert_eq!(result.var_name, "v");
        assert_eq!(result.loop_request, 4);
    }

    #[test]
    fn test_execute_iterate_flow_callbacks_and_iteration() {
        let base_url = "http://example.com";
        let init_extractor = Extractor {
            r#type: ExtractorType::Kval(vec!["items".to_string()]),
            name: Some("items".to_string()),
            group: None,
            internal: false,
            part: ExtractorPart::Header,
        };
        let init_http = build_http_request(base_url, vec![init_extractor]);
        let loop_http = build_http_request(&format!("{base_url}/{{{{item}}}}"), vec![]);
        let template = build_template(vec![init_http, loop_http]);
        let iterate_loop = IterateLoop {
            init_request: 0,
            var_name: String::from("item"),
            source_key: String::from("items"),
            loop_request: 1,
        };

        let mut cache = Cache::new(HashMap::new());
        cache.store(
            &CacheKey(Method::GET, vec![], base_url.to_string()),
            Some(crate::http::HttpResponse {
                req_url: base_url.to_string(),
                body: vec![],
                headers: vec![("items".to_string(), "a,b".to_string())],
                status_code: 200,
                duration: 0.1,
            }),
        );
        for suffix in ["a", "b"] {
            let url = format!("{base_url}/{suffix}");
            cache.store(
                &CacheKey(Method::GET, vec![], url.clone()),
                Some(crate::http::HttpResponse {
                    req_url: url,
                    body: vec![],
                    headers: vec![],
                    status_code: 200,
                    duration: 0.1,
                }),
            );
        }

        let ctx = build_iterate_context();
        let photon_ctx = build_photon_context();
        let options = ExecutionOptions::default();
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        let mut req_counter = 0;
        let matches: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let matches_ref = matches.clone();
        let callback = Some(move |_template: &Template, matched: &MatchResult| {
            matches_ref.borrow_mut().push(matched.matched_url.clone());
        });
        let continue_predicate: Option<fn() -> bool> = None;

        let executed = execute_iterate_flow(
            &template,
            &iterate_loop,
            base_url,
            &options,
            &mut curl,
            &RegexCache::new(),
            ctx.clone(),
            &photon_ctx,
            &mut req_counter,
            &mut cache,
            &callback,
            &continue_predicate,
        );

        assert!(executed);
        assert_eq!(matches.borrow().len(), 3);
        assert_eq!(
            ctx.borrow().get("items"),
            Some(Value::String("a,b".to_string()))
        );
        assert_eq!(
            ctx.borrow().get("item"),
            Some(Value::String("b".to_string()))
        );
    }

    #[test]
    fn test_execute_iterate_flow_missing_source_key() {
        let base_url = "http://example.com";
        let init_http = build_http_request(base_url, vec![]);
        let loop_http = build_http_request(&format!("{base_url}/{{{{item}}}}"), vec![]);
        let template = build_template(vec![init_http, loop_http]);
        let iterate_loop = IterateLoop {
            init_request: 0,
            var_name: String::from("item"),
            source_key: String::from("items"),
            loop_request: 1,
        };

        let mut cache = Cache::new(HashMap::new());
        cache.store(
            &CacheKey(Method::GET, vec![], base_url.to_string()),
            Some(crate::http::HttpResponse {
                req_url: base_url.to_string(),
                body: vec![],
                headers: vec![],
                status_code: 200,
                duration: 0.1,
            }),
        );

        let ctx = build_iterate_context();
        let photon_ctx = build_photon_context();
        let options = ExecutionOptions::default();
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        let mut req_counter = 0;
        let matches: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let matches_ref = matches.clone();
        let callback = Some(move |_template: &Template, matched: &MatchResult| {
            matches_ref.borrow_mut().push(matched.matched_url.clone());
        });
        let continue_predicate: Option<fn() -> bool> = None;

        let executed = execute_iterate_flow(
            &template,
            &iterate_loop,
            base_url,
            &options,
            &mut curl,
            &RegexCache::new(),
            ctx,
            &photon_ctx,
            &mut req_counter,
            &mut cache,
            &callback,
            &continue_predicate,
        );

        assert!(executed);
        assert_eq!(matches.borrow().len(), 1);
    }

    #[test]
    fn test_execute_iterate_flow_out_of_bounds_indices() {
        let base_url = "http://example.com";
        let template = build_template(vec![]);
        let iterate_loop = IterateLoop {
            init_request: 1,
            var_name: String::from("item"),
            source_key: String::from("items"),
            loop_request: 2,
        };

        let ctx = build_iterate_context();
        let photon_ctx = build_photon_context();
        let options = ExecutionOptions::default();
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        let mut req_counter = 0;
        let mut cache = Cache::new(HashMap::new());
        let callback: Option<fn(&Template, &MatchResult)> = None;
        let continue_predicate: Option<fn() -> bool> = None;

        let executed = execute_iterate_flow(
            &template,
            &iterate_loop,
            base_url,
            &options,
            &mut curl,
            &RegexCache::new(),
            ctx,
            &photon_ctx,
            &mut req_counter,
            &mut cache,
            &callback,
            &continue_predicate,
        );

        assert!(executed);
    }

    #[test]
    fn test_flow_short_circuit_and() {
        let base_url = "http://example.com";
        let http_one = build_http_request(base_url, vec![]);
        let http_two = build_http_request(&format!("{base_url}/second"), vec![]);
        let template = build_template(vec![http_one, http_two]);
        let compiled = compile_expression("http(1) && http(2)").unwrap();

        let mut cache = Cache::new(HashMap::new());
        store_response(&mut cache, base_url, 404);
        store_response(&mut cache, &format!("{base_url}/second"), 200);

        let ctx = build_iterate_context();
        let photon_ctx = build_photon_context();
        let options = ExecutionOptions::default();
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        let mut req_counter = 0;
        let matches: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let matches_ref = matches.clone();
        let callback = Some(move |_template: &Template, matched: &MatchResult| {
            matches_ref.borrow_mut().push(matched.matched_url.clone());
        });
        let continue_predicate: Option<fn() -> bool> = None;

        let executed = execute_flow_bytecodes(
            &template,
            &compiled,
            base_url,
            &options,
            &mut curl,
            &RegexCache::new(),
            ctx,
            &photon_ctx,
            &mut req_counter,
            &mut cache,
            &callback,
            &continue_predicate,
        );

        assert!(!executed);
        assert!(matches.borrow().is_empty());
    }

    #[test]
    fn test_flow_short_circuit_or() {
        let base_url = "http://example.com";
        let http_one = build_http_request(base_url, vec![]);
        let http_two = build_http_request(&format!("{base_url}/second"), vec![]);
        let template = build_template(vec![http_one, http_two]);
        let compiled = compile_expression("http(1) || http(2)").unwrap();

        let mut cache = Cache::new(HashMap::new());
        store_response(&mut cache, base_url, 200);
        store_response(&mut cache, &format!("{base_url}/second"), 200);

        let ctx = build_iterate_context();
        let photon_ctx = build_photon_context();
        let options = ExecutionOptions::default();
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        let mut req_counter = 0;
        let matches: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let matches_ref = matches.clone();
        let callback = Some(move |_template: &Template, matched: &MatchResult| {
            matches_ref.borrow_mut().push(matched.matched_url.clone());
        });
        let continue_predicate: Option<fn() -> bool> = None;

        let executed = execute_flow_bytecodes(
            &template,
            &compiled,
            base_url,
            &options,
            &mut curl,
            &RegexCache::new(),
            ctx,
            &photon_ctx,
            &mut req_counter,
            &mut cache,
            &callback,
            &continue_predicate,
        );

        assert!(executed);
        assert_eq!(matches.borrow().len(), 1);
        assert_eq!(matches.borrow()[0], base_url.to_string());
    }

    #[test]
    fn test_flow_chain_success() {
        let base_url = "http://example.com";
        let http_one = build_http_request(base_url, vec![]);
        let http_two = build_http_request(&format!("{base_url}/second"), vec![]);
        let template = build_template(vec![http_one, http_two]);
        let compiled = compile_expression("http(1) && http(2)").unwrap();

        let mut cache = Cache::new(HashMap::new());
        store_response(&mut cache, base_url, 200);
        store_response(&mut cache, &format!("{base_url}/second"), 200);

        let ctx = build_iterate_context();
        let photon_ctx = build_photon_context();
        let options = ExecutionOptions::default();
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        let mut req_counter = 0;
        let matches: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let matches_ref = matches.clone();
        let callback = Some(move |_template: &Template, matched: &MatchResult| {
            matches_ref.borrow_mut().push(matched.matched_url.clone());
        });
        let continue_predicate: Option<fn() -> bool> = None;

        let executed = execute_flow_bytecodes(
            &template,
            &compiled,
            base_url,
            &options,
            &mut curl,
            &RegexCache::new(),
            ctx,
            &photon_ctx,
            &mut req_counter,
            &mut cache,
            &callback,
            &continue_predicate,
        );

        assert!(executed);
        assert_eq!(matches.borrow().len(), 2);
    }

    #[test]
    fn test_flow_http_out_of_bounds() {
        let base_url = "http://example.com";
        let template = build_template(vec![]);
        let compiled = compile_expression("http(99)").unwrap();

        let mut cache = Cache::new(HashMap::new());
        let ctx = build_iterate_context();
        let photon_ctx = build_photon_context();
        let options = ExecutionOptions::default();
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        let mut req_counter = 0;
        let callback: Option<fn(&Template, &MatchResult)> = None;
        let continue_predicate: Option<fn() -> bool> = None;

        let executed = execute_flow_bytecodes(
            &template,
            &compiled,
            base_url,
            &options,
            &mut curl,
            &RegexCache::new(),
            ctx,
            &photon_ctx,
            &mut req_counter,
            &mut cache,
            &callback,
            &continue_predicate,
        );

        assert!(!executed);
    }

    #[test]
    fn test_integration_cat1_boolean_chain() {
        const YAML: &str = r#"
id: test-boolean-chain
info:
  name: Test Boolean Chain
  author: test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/endpoint1"]
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: ["{{BaseURL}}/endpoint2"]
    matchers:
      - type: status
        status: [200]
flow: "http(1) && http(2)"
"#;
        let template = load_template_from_yaml(YAML).unwrap();
        assert!(matches!(
            template.flow,
            Some(FlowExpression::BooleanChain(_))
        ));
        assert!(template.http.len() >= 2);
    }

    #[test]
    fn test_integration_cat2_iterate_loop() {
        const YAML: &str = r#"
id: test-iterate-loop
info:
  name: Test Iterate Loop
  author: test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/init"]
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: ["{{BaseURL}}/{{x}}"]
    matchers:
      - type: status
        status: [200]
flow: "http(1)\nfor (let x of iterate(template.vals)) {\n  set(\"x\", x)\n  http(2)\n}"
"#;
        let template = load_template_from_yaml(YAML).unwrap();
        match &template.flow {
            Some(FlowExpression::IterateLoop {
                init_request,
                var_name,
                source_key,
                loop_request,
            }) => {
                assert_eq!(*init_request, 0);
                assert_eq!(var_name, "x");
                assert_eq!(source_key, "vals");
                assert_eq!(*loop_request, 1);
            }
            _ => panic!("Expected IterateLoop variant"),
        }
    }

    #[test]
    fn test_integration_unsupported_loads_and_skips() {
        const YAML: &str = r#"
id: test-unsupported-flow
info:
  name: Test Unsupported Flow
  author: test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/ignored"]
    matchers:
      - type: status
        status: [200]
flow: "http(1); var path = \"\"; if (template.data) { path = \"x\"; }"
"#;
        let template = load_template_from_yaml(YAML).unwrap();
        assert!(matches!(
            template.flow,
            Some(FlowExpression::Unsupported(_))
        ));

        let base_url = "http://example.com";
        let mut cache = Cache::new(HashMap::new());
        let ctx = build_global_context();
        let photon_ctx = build_photon_context();
        let options = ExecutionOptions::default();
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        let mut req_counter = 0;
        let callback: Option<fn(&Template, &MatchResult)> = None;
        let continue_predicate: Option<fn() -> bool> = None;

        let executed = template.execute(
            base_url,
            &options,
            &mut curl,
            ctx,
            &photon_ctx,
            &mut req_counter,
            &mut cache,
            &RegexCache::new(),
            &callback,
            &continue_predicate,
        );

        assert!(executed);
    }

    #[test]
    fn test_integration_no_flow_regression() {
        const YAML: &str = r#"
id: test-no-flow
info:
  name: Test No Flow
  author: test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/no-flow"]
    matchers:
      - type: status
        status: [200]
"#;
        let template = load_template_from_yaml(YAML).unwrap();
        assert!(template.flow.is_none());
    }

    // --- Rejection tests ---

    #[test]
    fn test_reject_boolean_chain() {
        assert!(parse_iterate_pattern("http(1) && http(2)").is_none());
    }

    #[test]
    fn test_reject_conditional() {
        assert!(parse_iterate_pattern("if (template.x) { http(1) }").is_none());
    }

    #[test]
    fn test_reject_json_parse() {
        assert!(parse_iterate_pattern("JSON.parse(template.data)").is_none());
    }

    #[test]
    fn test_reject_complex_flow_with_var_declaration() {
        // CVE-2025-51586 style - complex flow with var declarations and conditionals
        let flow = r#"http(1);
  var path = "";
  if (template["matchedpath"] && template["matchedpath"].length) {
    for (let p of iterate(template["matchedpath"])) {
      path = p;
      break;
    }
  }"#;
        assert!(parse_iterate_pattern(flow).is_none());
    }

    #[test]
    fn test_reject_nested_loops() {
        // GCP-style nested iterate (multi-protocol, out of scope)
        let flow = r#"code(1)
  for(let projectId of iterate(template.projectIds)){
    set("projectId", projectId)
    code(2)
    for(let network of iterate(template.networks)){
      set("network", network)
      code(3)
    }
  }"#;
        assert!(parse_iterate_pattern(flow).is_none());
    }

    #[test]
    fn test_reject_named_request_ids() {
        // headless/webpack-sourcemap.yaml style - named request IDs
        let flow = r#"headless();
  http("check_base_srcmap_inline");
  for (let scripturi of iterate(template["allscripts"])) {
    set("scripturi", scripturi);
    http("check_for_srcmap_header");
  }"#;
        assert!(parse_iterate_pattern(flow).is_none());
    }

    #[test]
    fn test_reject_empty_string() {
        assert!(parse_iterate_pattern("").is_none());
    }

    #[test]
    fn test_reject_http_zero() {
        // http(0) would underflow on 1-to-0 index conversion
        let flow =
            "http(0)\nfor (let x of iterate(template.data)) {\n  set(\"x\", x)\n  http(1)\n}";
        assert!(parse_iterate_pattern(flow).is_none());
    }

    #[test]
    fn test_reject_iterate_with_index_access() {
        // CVE-2017-8046 style — iterate()[0] not a for loop
        let flow = r#"http(1)
  set("endpoint", iterate(template.endpoint)[0])
  http(2)"#;
        assert!(parse_iterate_pattern(flow).is_none());
    }

    #[test]
    fn test_reject_mixed_boolean_and_iterate() {
        // CVE-2020-13640 style — set() + boolean chain, not a simple for loop
        let flow = r#"http(1)
  set("postid", iterate(template.postid)[0])
  http(2) && http(3)"#;
        assert!(parse_iterate_pattern(flow).is_none());
    }
}
