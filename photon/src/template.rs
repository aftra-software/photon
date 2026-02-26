use core::str;
use std::{
    cell::RefCell,
    fmt::{Display, Formatter},
    rc::Rc,
};

use crate::{
    PhotonContext,
    cache::{Cache, RegexCache},
    get_config,
    http::{CurlHandle, HttpReq, HttpResponse},
    matcher::{Extractor, Matcher},
    template_executor::ExecutionOptions,
};
use itertools::Itertools;
use photon_dsl::{
    dsl::{CompiledExpression, Value, VariableContainer},
    parser::compile_expression_validated,
};
use rustc_hash::{FxHashMap, FxHashSet};

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Unknown,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
            Self::Unknown => "Unknown",
        })
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum Method {
    GET,
    POST,
    HEAD,
    PATCH,
    DELETE,
    OPTIONS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum Condition {
    AND,
    OR,
}

#[derive(Debug, Clone)]
pub struct Classification {
    pub cve_id: Vec<String>,
    pub cwe_id: Vec<String>,
    pub cvss_metrics: Option<String>,
    pub cvss_score: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub author: Vec<String>,
    pub description: String,
    pub remediation: Option<String>,
    pub classification: Option<Classification>,
    pub severity: Severity,
    pub reference: Vec<String>,
    pub tags: Vec<String>,
}

type AttackPayloads = Vec<(String, Vec<Value>)>;

#[derive(Debug, Clone, Copy)]
pub enum AttackMode {
    Batteringram, // Default
    Clusterbomb,
    Pitchfork,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub extractors: Vec<Extractor>,
    pub matchers: Vec<Matcher>,
    pub payloads: AttackPayloads,
    pub attack_mode: AttackMode,
    pub matchers_condition: Condition,
    pub path: Vec<HttpReq>,
}

#[derive(Debug, PartialEq)]
pub enum ContextScope {
    Global,
    Template,
    Request,
}

#[derive(Debug)]
pub struct Context {
    pub variables: FxHashMap<String, Value>,
    pub parent: Option<Rc<RefCell<Context>>>,
    pub scope: ContextScope,
}

impl Context {
    pub fn insert_str(&mut self, key: &str, value: &str) {
        self.variables
            .insert(key.to_string(), Value::String(value.to_string()));
    }

    pub fn insert_int(&mut self, key: &str, value: i64) {
        self.variables.insert(key.to_string(), Value::Int(value));
    }

    pub fn insert(&mut self, key: &str, value: Value) {
        self.variables.insert(key.to_string(), value);
    }

    /// `scope` must be the scope of the context, or a parent scope of the context.
    pub fn insert_in_scope(&mut self, scope: ContextScope, key: &str, value: Value) {
        if self.scope == scope {
            self.insert(key, value);
        } else {
            self.parent
                .as_ref()
                .expect("Parent to exist, orphan context?")
                .borrow_mut()
                .insert_in_scope(scope, key, value);
        }
    }
}

// Recursive context container, check current variables, if not found check parent
impl VariableContainer for Context {
    fn contains_key(&self, key: &str) -> bool {
        if let Some(parent) = &self.parent {
            self.variables.contains_key(key) || parent.borrow().contains_key(key)
        } else {
            self.variables.contains_key(key)
        }
    }

    fn get(&self, key: &str) -> Option<Value> {
        if self.contains_key(key) {
            if self.variables.contains_key(key) {
                Some(self.variables.get(key).unwrap().clone())
            } else {
                Some(self.parent.as_ref().unwrap().borrow().get(key).unwrap())
            }
        } else {
            None
        }
    }
}

impl VariableContainer for &Context {
    fn contains_key(&self, key: &str) -> bool {
        (*self).contains_key(key)
    }

    fn get(&self, key: &str) -> Option<Value> {
        (*self).get(key)
    }
}

#[derive(Debug, Clone)]
pub struct Template {
    pub id: String,
    pub info: Info,
    pub http: Vec<HttpRequest>,
    pub flow: Option<CompiledExpression>,
    pub variables: Vec<(String, Value)>,
    pub dsl_variables: Vec<(String, String)>, // DSL variables, lazily compiled
}

// TODO: MatchResult values from extractors (figure out how we want to handle that logic as well)
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct MatchResult {
    pub name: Option<String>,
    pub matched_url: String,
    pub internal: bool,
}

impl Severity {
    pub fn colored_string(&self) -> String {
        match self {
            Self::Critical => "\x1b[0;35mcritical\x1b[0m".to_string(),
            Self::High => "\x1b[0;31mhigh\x1b[0m".to_string(),
            Self::Medium => "\x1b[0;33mmedium\x1b[0m".to_string(),
            Self::Low => "\x1b[0;90mlow\x1b[0m".to_string(),
            Self::Info => "\x1b[0;36minfo\x1b[0m".to_string(),
            Self::Unknown => "\x1b[0;90munknown\x1b[0m".to_string(),
        }
    }
}

enum AttackIteratorImpl<'a> {
    Simple {
        inner: &'a AttackPayloads,
        idx: usize,
        stop_idx: usize,
    },
    Clusterbomb {
        keys: Vec<&'a String>,
        iter: Box<dyn Iterator<Item = Vec<Value>> + 'a>,
    },
    Noop {
        done: bool,
    },
}

struct AttackIterator<'a> {
    inner: AttackIteratorImpl<'a>,
}

impl<'a> AttackIterator<'a> {
    fn new(inner: &'a AttackPayloads, mode: AttackMode) -> Self {
        if inner.is_empty() {
            return AttackIterator {
                inner: AttackIteratorImpl::Noop { done: false },
            };
        }

        let inner_impl = match mode {
            AttackMode::Pitchfork | AttackMode::Batteringram => {
                let stop_idx = inner
                    .iter()
                    .map(|(_, values)| values.len())
                    .min()
                    .unwrap_or(0);
                AttackIteratorImpl::Simple {
                    inner,
                    idx: 0,
                    stop_idx,
                }
            }
            AttackMode::Clusterbomb => {
                let keys: Vec<_> = inner.iter().map(|(k, _)| k).collect();
                let value_vecs: Vec<&[Value]> = inner.iter().map(|(_, v)| v.as_slice()).collect();
                let iter = value_vecs
                    .into_iter()
                    .multi_cartesian_product()
                    .map(|combo| combo.into_iter().cloned().collect());
                AttackIteratorImpl::Clusterbomb {
                    keys,
                    iter: Box::new(iter),
                }
            }
        };

        AttackIterator { inner: inner_impl }
    }
}

impl<'a> Iterator for AttackIterator<'a> {
    type Item = Vec<(String, Value)>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            AttackIteratorImpl::Noop { done } => {
                if *done {
                    None
                } else {
                    *done = true;
                    Some(vec![])
                }
            }
            AttackIteratorImpl::Simple {
                inner,
                idx,
                stop_idx,
            } => {
                if *idx >= *stop_idx {
                    return None;
                }

                let mut ret = Vec::with_capacity(inner.len());
                for (key, values) in inner.iter() {
                    ret.push((key.clone(), values[*idx].clone()));
                }
                *idx += 1;
                Some(ret)
            }
            AttackIteratorImpl::Clusterbomb { keys, iter } => iter.next().map(|values| {
                keys.iter()
                    .zip(values)
                    .map(|(k, v)| ((*k).clone(), v))
                    .collect()
            }),
        }
    }
}

impl HttpRequest {
    fn handle_response(
        &self,
        resp: HttpResponse,
        idx: usize,
        ctx: &mut Context,
        regex_cache: &RegexCache,
        photon_ctx: &PhotonContext,
    ) -> Vec<MatchResult> {
        ctx.insert_str(
            &format!("body_{}", idx + 1),
            &String::from_utf8_lossy(&resp.body),
        );
        ctx.insert_str("body", &String::from_utf8_lossy(&resp.body));

        // TODO: Should this be a Float?
        ctx.insert_int("duration", resp.duration as i64);
        ctx.insert_int(&format!("status_code_{}", idx + 1), resp.status_code as i64);
        ctx.insert_int("status_code", resp.status_code as i64);
        ctx.insert_str(
            "header",
            resp.headers
                .iter()
                .fold(String::with_capacity(512), |acc, hed| {
                    format!("{acc}{}: {}\n", hed.0, hed.1)
                })
                .trim(),
        );
        for extractor in self.extractors.iter() {
            if let Some(name) = &extractor.name {
                if let Some(res) = extractor.extract(&resp, regex_cache, &ctx, photon_ctx) {
                    ctx.insert_in_scope(ContextScope::Template, &name, res);
                }
            }
        }

        let mut matches = Vec::new();
        for matcher in self.matchers.iter() {
            // Negative XOR matches
            if matcher.negative ^ matcher.matches(&resp, regex_cache, &ctx, photon_ctx) {
                matches.push(MatchResult {
                    matched_url: resp.req_url.clone(),
                    name: matcher.name.clone(),
                    internal: matcher.internal,
                });
            }
        }
        matches
    }

    fn all_payload_contexts(
        &self,
        parent_ctx: Rc<RefCell<Context>>,
    ) -> impl Iterator<Item = Context> + use<'_> {
        AttackIterator::new(&self.payloads, self.attack_mode).map(move |attack_values| {
            let mut ctx = Context {
                variables: FxHashMap::default(),
                parent: Some(parent_ctx.clone()),
                scope: ContextScope::Request,
            };
            for (key, value) in attack_values {
                // TODO: for Value::String values, put them through bake_ctx, since some templates contain DSL things in payloads
                ctx.insert(&key, value);
            }
            ctx
        })
    }

    fn execute_single_request(
        &self,
        idx: usize,
        req: &HttpReq,
        base_url: &str,
        options: &ExecutionOptions,
        curl: &mut CurlHandle,
        ctx: &mut Context,
        photon_ctx: &PhotonContext,
        req_counter: &mut u32,
        cache: &mut Cache,
        regex_cache: &RegexCache,
    ) -> Option<FxHashSet<MatchResult>> {
        let resp = req.do_request(base_url, options, curl, ctx, photon_ctx, req_counter, cache)?;
        let matchers_result = self.handle_response(resp, idx, ctx, regex_cache, photon_ctx);

        if !matchers_result.is_empty() {
            match self.matchers_condition {
                Condition::AND => {
                    if matchers_result.len() == self.matchers.len() {
                        return Some(FxHashSet::from_iter(matchers_result));
                    }
                }
                Condition::OR => {
                    if !matchers_result.is_empty() {
                        return Some(FxHashSet::from_iter(matchers_result));
                    }
                }
            }
        }

        None
    }

    fn execute<C>(
        &self,
        base_url: &str,
        options: &ExecutionOptions,
        curl: &mut CurlHandle,
        regex_cache: &RegexCache,
        parent_ctx: Rc<RefCell<Context>>,
        photon_ctx: &PhotonContext,
        req_counter: &mut u32,
        cache: &mut Cache,
        continue_predicate: &Option<C>,
    ) -> FxHashSet<MatchResult>
    where
        C: Fn() -> bool,
    {
        let payload_contexts = self.all_payload_contexts(parent_ctx);

        for mut context in payload_contexts {
            for (idx, req) in self.path.iter().enumerate() {
                // Check if we're supposed to continue scanning or not
                if let Some(pred) = continue_predicate
                    && !pred()
                {
                    return FxHashSet::default();
                }

                // XXX: Signature will become nicer once ExecutorContext refactoring is done
                if let Some(matches) = self.execute_single_request(
                    idx,
                    req,
                    base_url,
                    options,
                    curl,
                    &mut context,
                    photon_ctx,
                    req_counter,
                    cache,
                    regex_cache,
                ) {
                    return matches;
                }
            }
        }

        FxHashSet::default()
    }
}

impl Template {
    // TODO: Look into reducing the number of parameters
    // e.g. Refactor TemplateExecutor to forward some ExecutorContext with execution info like options, context, caches, request counter etc
    // There's a lot of stuff we need to pass from a higher context into the templates & requests
    pub fn execute<K, C>(
        &self,
        base_url: &str,
        options: &ExecutionOptions,
        curl: &mut CurlHandle,
        parent_ctx: Rc<RefCell<Context>>,
        photon_ctx: &PhotonContext, // TODO: we can move parent_ctx into here, options as well
        req_counter: &mut u32,
        cache: &mut Cache,
        regex_cache: &RegexCache,
        callback: &Option<K>,
        continue_predicate: &Option<C>,
    ) -> bool
    where
        K: Fn(&Template, &MatchResult),
        C: Fn() -> bool,
    {
        let ctx = Rc::from(RefCell::from(Context {
            variables: FxHashMap::from_iter(self.variables.iter().cloned()),
            parent: Some(parent_ctx),
            scope: ContextScope::Template,
        }));
        let mut evaluated = FxHashSet::default();
        loop {
            let mut successful = 0;
            for (key, value) in &self.dsl_variables {
                // If this key already exists,
                if evaluated.contains(key) {
                    continue;
                }

                if let Ok(expr) = compile_expression_validated(value, &photon_ctx.functions) {
                    // Need to make sure not to hold an immutable borrow on ctx after executing
                    let out = { expr.execute(&*ctx.borrow(), &photon_ctx.functions) };
                    if let Ok(res) = out {
                        ctx.borrow_mut().insert(key, res);
                        evaluated.insert(key);
                        successful += 1;
                    }
                } else {
                    debug!("Failed to compile expression: {value}")
                }
            }
            // Break when no more variables to compile
            if successful == 0 {
                break;
            }
        }

        for http in &self.http {
            // Check if we're supposed to continue scanning or not
            if let Some(pred) = continue_predicate
                && !pred()
            {
                return false;
            }

            let match_results: FxHashSet<MatchResult> = http.execute(
                base_url,
                options,
                curl,
                regex_cache,
                ctx.clone(),
                photon_ctx,
                req_counter,
                cache,
                continue_predicate,
            );
            // Do a callback for all non-internal matches
            for matched in &match_results {
                if !matched.internal {
                    if let Some(callback) = callback {
                        callback(self, matched)
                    }
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use itertools::iproduct;
    use photon_dsl::dsl::Value;
    use rustc_hash::FxHashMap;

    use crate::template::{AttackIterator, AttackMode, Context, ContextScope};

    #[test]
    fn test_insert_in_scope() {
        let global_ctx = Rc::from(RefCell::from(Context {
            parent: None,
            variables: FxHashMap::default(),
            scope: ContextScope::Global,
        }));

        let template_ctx = Rc::from(RefCell::from(Context {
            parent: Some(global_ctx),
            variables: FxHashMap::default(),
            scope: ContextScope::Template,
        }));

        let request_ctx = Rc::from(RefCell::from(Context {
            parent: Some(template_ctx),
            variables: FxHashMap::default(),
            scope: ContextScope::Request,
        }));

        {
            let mut borrowed = request_ctx.borrow_mut();
            // Bypass ContextScope::Template and insert straight into Global scope
            borrowed.insert_in_scope(ContextScope::Global, "global test", Value::Int(5));
        }

        // ew, assert the inserted value does exist in the global scope
        assert!(
            request_ctx
                .borrow()
                .parent
                .as_ref()
                .unwrap()
                .borrow()
                .parent
                .as_ref()
                .unwrap()
                .borrow()
                .variables
                .get("global test")
                == Some(&Value::Int(5))
        );
    }

    #[test]
    #[should_panic]
    fn test_insert_invalid_scope() {
        let global_ctx = Rc::from(RefCell::from(Context {
            parent: None,
            variables: FxHashMap::default(),
            scope: ContextScope::Global,
        }));

        let mut template_ctx = Context {
            parent: Some(global_ctx),
            variables: FxHashMap::default(),
            scope: ContextScope::Template,
        };

        // This panics because ContextScope::Request can only exist below ContextScope::Template and not above
        template_ctx.insert_in_scope(ContextScope::Request, "blehh", Value::Boolean(false));
    }

    fn valuestring(s: &str) -> Value {
        Value::String(String::from(s))
    }

    #[test]
    fn test_clusterbomb_iteration() {
        let username = String::from("username");
        let password = String::from("password");
        let method = String::from("method");
        let payloads = vec![
            (
                username.clone(),
                vec![valuestring("test"), valuestring("admin")],
            ),
            (
                password.clone(),
                vec![
                    valuestring("12345"),
                    valuestring("test"),
                    valuestring("admin"),
                ],
            ),
            (
                method.clone(),
                vec![valuestring("http"), valuestring("https")],
            ),
        ];

        let iterator = AttackIterator::new(&payloads, AttackMode::Clusterbomb);
        let attacks: Vec<_> = iterator.into_iter().collect();
        assert_eq!(12, attacks.len());
        for (u, p, m) in iproduct!(
            ["test", "admin"],
            ["12345", "test", "admin"],
            ["http", "https"],
        ) {
            assert!(attacks.contains(&vec![
                (username.clone(), valuestring(u)),
                (password.clone(), valuestring(p)),
                (method.clone(), valuestring(m)),
            ]))
        }
    }
}
