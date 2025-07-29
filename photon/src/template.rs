use core::str;
use std::{cell::RefCell, rc::Rc};

use crate::{
    cache::{Cache, RegexCache},
    get_config,
    http::{CurlHandle, HttpReq, HttpResponse},
    matcher::{Extractor, Matcher},
    template_executor::ExecutionOptions,
    PhotonContext,
};
use photon_dsl::{
    dsl::{Value, VariableContainer},
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

type AttackPayloads = FxHashMap<String, Vec<Value>>;

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
    pub variables: Vec<(String, Value)>,
    pub dsl_variables: Vec<(String, String)>, // DSL variables, lazily compiled
}

// TODO: MatchResult values from extractors (figure out how we want to handle that logic as well)
#[derive(Debug)]
pub struct MatchResult {
    pub name: String,
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

struct AttackIterator<'a> {
    inner: &'a AttackPayloads,
    is_noop: bool,
    idx: usize,
    stop_idx: usize,
    #[allow(unused)]
    mode: AttackMode,
}

impl<'a> AttackIterator<'a> {
    fn new(inner: &'a AttackPayloads, mode: AttackMode) -> Self {
        // TODO: Different logic for Clusterbomb
        let is_noop = inner.is_empty();
        let stop_idx = if !is_noop {
            inner.values().map(|values| values.len()).min().unwrap_or(0)
        } else {
            1 // Return empty vec for 1 iteration when not attacking
        };

        AttackIterator {
            inner,
            mode,
            is_noop: inner.is_empty(),
            idx: 0,
            stop_idx,
        }
    }
}

impl<'a> Iterator for AttackIterator<'a> {
    type Item = Vec<(String, Value)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx == self.stop_idx {
            return None;
        }

        let ret = if self.is_noop {
            Some(vec![])
        } else {
            // TODO: Handle Clusterbomb differently later (all possible combinations of all parameters)
            // Pitchfork and Batteringram behave the same, Batteringram is for 1 variable, Pitchfork for multiple
            // So we implement them both in the exact same way.
            let mut ret = Vec::with_capacity(4);
            for (key, values) in self.inner {
                ret.push((key.clone(), values[self.idx].clone()));
            }

            Some(ret)
        };

        self.idx += 1;

        ret
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
                    name: matcher.name.clone().unwrap_or(String::new()),
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
    ) -> Option<Vec<MatchResult>> {
        let resp = req.do_request(base_url, options, curl, ctx, photon_ctx, req_counter, cache)?;
        let matchers_result = self.handle_response(resp, idx, ctx, regex_cache, photon_ctx);

        if !matchers_result.is_empty() {
            match self.matchers_condition {
                Condition::AND => {
                    if matchers_result.len() == self.matchers.len() {
                        return Some(matchers_result);
                    }
                }
                Condition::OR => {
                    if !matchers_result.is_empty() {
                        return Some(matchers_result);
                    }
                }
            }
        }

        None
    }

    fn execute(
        &self,
        base_url: &str,
        options: &ExecutionOptions,
        curl: &mut CurlHandle,
        regex_cache: &RegexCache,
        parent_ctx: Rc<RefCell<Context>>,
        photon_ctx: &PhotonContext,
        req_counter: &mut u32,
        cache: &mut Cache,
    ) -> Vec<MatchResult> {
        let payload_contexts = self.all_payload_contexts(parent_ctx);

        for mut context in payload_contexts {
            for (idx, req) in self.path.iter().enumerate() {
                // Signature will become nicer once ExecutorContext refactoring is done
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

        vec![]
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
        K: Fn(&Template, Option<String>),
        C: Fn() -> bool,
    {
        let ctx = Rc::from(RefCell::from(Context {
            variables: FxHashMap::from_iter(self.variables.iter().cloned()),
            parent: Some(parent_ctx),
            scope: ContextScope::Template,
        }));
        for (key, value) in &self.dsl_variables {
            if let Ok(expr) = compile_expression_validated(value, &photon_ctx.functions) {
                // Need to make sure not to hold an immutable borrow on ctx after executing
                let out = { expr.execute(&*ctx.borrow(), &photon_ctx.functions) };
                if let Ok(res) = out {
                    ctx.borrow_mut().insert(key, res);
                }
            } else {
                debug!("Failed to compile expression: {value}")
            }
        }

        for http in &self.http {
            // Check if we're supposed to continue scanning or not
            if continue_predicate.is_some() && !continue_predicate.as_ref().unwrap()() {
                return false;
            }

            let match_results = http.execute(
                base_url,
                options,
                curl,
                regex_cache,
                ctx.clone(),
                photon_ctx,
                req_counter,
                cache,
            );
            if !match_results.is_empty() {
                // Stupid string printing, for the cases where we have templates like
                // missing-header:x-iframe-whatever
                // missing-header:content-security-policy
                // And want to display the different cases that were matched
                let mut unique_names = FxHashSet::default();
                for matched in &match_results {
                    if !matched.internal {
                        unique_names.insert(matched.name.clone());
                    }
                }
                for name in unique_names {
                    let name = if name.is_empty() { None } else { Some(name) };
                    if let Some(callback) = callback {
                        callback(self, name)
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

    use photon_dsl::dsl::Value;
    use rustc_hash::FxHashMap;

    use crate::template::{Context, ContextScope};

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
}
