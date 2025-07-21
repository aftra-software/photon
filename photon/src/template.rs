use core::str;
use std::{cell::RefCell, rc::Rc};

use crate::{
    cache::{Cache, RegexCache},
    get_config,
    http::{bake_ctx, get_bracket_pattern, HttpReq, HttpResponse},
    template_executor::ExecutionOptions,
    PhotonContext,
};
use curl::easy::{Easy2, Handler, WriteError};
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

#[derive(Debug, Clone)]
pub enum MatcherType {
    Word(Vec<String>),
    DSL(Vec<CompiledExpression>),
    Regex(Vec<u32>), // indicies into RegexCache
    Status(Vec<u32>),
}

#[derive(Debug, Clone)]
pub enum ExtractorType {
    Matcher(MatcherType),
    Kval(Vec<String>),
}

#[derive(Debug, Clone, Copy)]
pub enum ExtractorPart {
    HeaderCookie, // Either Header or Cookie, with Header having priority
    Header,
    Cookie,
    // Response Parts
    Body,
    Raw,
    All,
    Response, // Seems to be an alias for All, https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md#httprequest
}

#[derive(Debug, Clone, Copy)]
pub enum ResponsePart {
    Body,
    Raw,
    Header,
    All,
    Response, // Seems to be an alias for All, https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md#httprequest
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum Condition {
    AND,
    OR,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub author: String,
    pub description: String,
    pub severity: Severity,
    pub reference: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Matcher {
    pub r#type: MatcherType,
    pub name: Option<String>,
    pub negative: bool,
    pub group: Option<i64>, // Regex group number, None represents entire regex match
    pub internal: bool,     // Used for workflows, matches, but does not print
    pub part: ResponsePart,
    pub condition: Condition,
}

#[derive(Debug, Clone)]
pub struct Extractor {
    pub r#type: ExtractorType,
    pub name: Option<String>,
    pub group: Option<i64>, // Regex group number, None represents entire regex match
    pub internal: bool,     // Used for workflows, matches, but does not print
    pub part: ExtractorPart,
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

#[derive(Debug)]
pub struct Context {
    pub variables: FxHashMap<String, Value>,
    pub parent: Option<Rc<RefCell<Context>>>,
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

// TODO: MatchResult value from extractor (figure out how we want to handle that logic as well)
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

fn extractor_part_to_string(data: &HttpResponse, part: ExtractorPart) -> String {
    match part {
        // Map 1:1 Extractor -> Response parts
        ExtractorPart::All => response_to_string(data, ResponsePart::All),
        ExtractorPart::Response => response_to_string(data, ResponsePart::Response),
        ExtractorPart::Body => response_to_string(data, ResponsePart::Body),
        ExtractorPart::Raw => response_to_string(data, ResponsePart::Raw),
        // Cookies are in Headers, so HeaderCookie maps to Headers string
        ExtractorPart::Header | ExtractorPart::HeaderCookie => {
            response_to_string(data, ResponsePart::Header)
        }

        // Concatenated all cookie headers into a single string
        ExtractorPart::Cookie => data
            .headers
            .iter()
            .filter(|(key, _)| key.to_lowercase() == "set-cookie")
            .map(|(_, value)| format!("{value}\n"))
            .collect::<Vec<String>>()
            .concat(),
    }
}

// Get (Key, Value) pairs from cookies
fn extractor_get_cookies(data: &HttpResponse) -> Vec<(String, String)> {
    data.headers
        .iter()
        .filter(|(key, _)| key.to_lowercase() == "set-cookie")
        .filter_map(|(_, value)| {
            let cookie_kv = value.split(';').next().unwrap().split_once('=');
            if let Some((key, value)) = cookie_kv {
                // https://docs.projectdiscovery.io/templates/reference/extractors#kval-extractor
                // Nuclei kval extractors don't support dashes, so we modify the key to conform to their spec
                Some((String::from(key).replace('-', "_"), String::from(value)))
            } else {
                None
            }
        })
        .collect::<Vec<(String, String)>>()
}

fn response_to_string(data: &HttpResponse, part: ResponsePart) -> String {
    match part {
        ResponsePart::All | ResponsePart::Response => {
            // TODO: Actually return proper All, now easier using CURL
            let mut parts = vec![];
            data.headers
                .iter()
                .for_each(|(k, v)| parts.push(format!("{k}: {v}\n")));
            parts.push(data.body.clone());
            parts.concat()
        }
        ResponsePart::Body => data.body.clone(),
        ResponsePart::Header => data
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}\n"))
            .collect::<Vec<String>>()
            .concat(),
        ResponsePart::Raw => {
            // TODO: Actually return Raw
            let mut parts = vec![];
            data.headers
                .iter()
                .for_each(|(k, v)| parts.push(format!("{k}: {v}\n")));
            parts.push(data.body.clone());
            parts.concat()
        }
    }
}

fn contains_with_dsl(
    haystack: &str,
    needle: &str,
    ctx: &Context,
    photon_ctx: &PhotonContext,
) -> bool {
    // This can be made cleaner with Rust 2024 edition
    // But that requires Rust 1.88!
    if needle.contains("{{") {
        if get_bracket_pattern().is_match(needle) {
            if let Some(baked) = bake_ctx(needle, ctx, photon_ctx) {
                haystack.contains(&baked.to_string())
            } else {
                false
            }
        } else {
            haystack.contains(needle)
        }
    } else {
        haystack.contains(needle)
    }
}

impl Matcher {
    pub fn matches(
        &self,
        data: &HttpResponse,
        regex_cache: &RegexCache,
        context: &Context,
        photon_context: &PhotonContext,
    ) -> bool {
        if let MatcherType::Status(_) = self.r#type {
            return self.matches_status(data.status_code);
        }

        let data = response_to_string(data, self.part);
        match &self.r#type {
            MatcherType::DSL(dsls) => {
                if self.condition == Condition::OR {
                    dsls.iter().any(|expr| {
                        let res = expr.execute(&context, &photon_context.functions);
                        res.is_ok() && (res.unwrap() == Value::Boolean(true))
                    })
                } else {
                    dsls.iter().all(|expr| {
                        let res = expr.execute(&context, &photon_context.functions);
                        res.is_ok() && (res.unwrap() == Value::Boolean(true))
                    })
                }
            }
            MatcherType::Regex(regexes) => {
                if self.condition == Condition::OR {
                    regexes
                        .iter()
                        .any(|pattern| regex_cache.matches(*pattern, &data))
                } else {
                    regexes
                        .iter()
                        .all(|pattern| regex_cache.matches(*pattern, &data))
                }
            }
            MatcherType::Word(words) => {
                if self.condition == Condition::OR {
                    words
                        .iter()
                        .any(|needle| contains_with_dsl(&data, needle, context, photon_context))
                } else {
                    words
                        .iter()
                        .all(|needle| contains_with_dsl(&data, needle, context, photon_context))
                }
            }
            MatcherType::Status(_) => false,
        }
    }

    fn matches_status(&self, status: u32) -> bool {
        match &self.r#type {
            MatcherType::Status(statuses) => statuses.contains(&status),
            _ => unreachable!("Cannot match status when type != MatcherType::Status"),
        }
    }
}

impl Extractor {
    // TODO: Allow multiple returns, with matchers being ran with all permutations
    // of all possible extracted values? That's the logic according to testing with Nuclei
    // where the matcher is ran like this pseudo logic:
    // values.iter().any(|val| {
    //    context.set(name, val)
    //    matcher.matches(context)
    //})
    // if either matches, both values are added into the match
    pub fn extract(
        &self,
        data: &HttpResponse,
        regex_cache: &RegexCache,
        context: &Context,
        photon_context: &PhotonContext,
    ) -> Option<Value> {
        match &self.r#type {
            ExtractorType::Matcher(matcher) => {
                if let MatcherType::Status(_) = matcher {
                    return self.matches_status(data.status_code);
                }

                let data = extractor_part_to_string(data, self.part);
                match &matcher {
                    MatcherType::DSL(dsls) => dsls
                        .iter()
                        .filter_map(|expr| expr.execute(&context, &photon_context.functions).ok())
                        .next(),
                    MatcherType::Regex(regexes) => regexes
                        .iter()
                        .filter_map(|pattern| {
                            regex_cache.match_group(
                                *pattern,
                                &data,
                                self.group.unwrap_or(0) as usize,
                            )
                        })
                        .next()
                        .map(Value::String),
                    MatcherType::Word(_) => {
                        debug!("Extractor does not support Word matching");
                        None
                    }
                    MatcherType::Status(_) => None,
                }
            }
            ExtractorType::Kval(fields) => {
                let cookies = extractor_get_cookies(data);
                match self.part {
                    ExtractorPart::Cookie | ExtractorPart::Header => {
                        let kv = match self.part {
                            ExtractorPart::Cookie => &cookies,
                            ExtractorPart::Header => &data.headers,
                            _ => unreachable!(),
                        };
                        for field in fields {
                            if let Some((_, value)) = kv
                                .iter()
                                .find(|(k, _)| k.to_lowercase() == field.to_lowercase())
                            {
                                return Some(Value::String(value.clone()));
                            }
                        }
                    }
                    ExtractorPart::HeaderCookie => {
                        for field in fields {
                            for kv in [&data.headers, &cookies] {
                                if let Some((_, value)) = kv
                                    .iter()
                                    .find(|(k, _)| k.to_lowercase() == field.to_lowercase())
                                {
                                    return Some(Value::String(value.clone()));
                                }
                            }
                        }
                    }
                    _ => return None,
                }
                None
            }
        }
    }

    fn matches_status(&self, status: u32) -> Option<Value> {
        match &self.r#type {
            // TODO: Maybe this should be different/Not implemented for Extractor
            ExtractorType::Matcher(MatcherType::Status(_)) => Some(Value::Int(status as i64)),
            _ => unreachable!("Cannot match status when type != MatcherType::Status"),
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
        matches: &mut Vec<MatchResult>,
        idx: usize,
        ctx: &mut Context,
        regex_cache: &RegexCache,
        photon_context: &PhotonContext,
    ) {
        ctx.insert_str(&format!("body_{}", idx + 1), &resp.body);
        ctx.insert_str("body", &resp.body);

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
            if extractor.name.is_some() {
                if let Some(res) = extractor.extract(&resp, regex_cache, &ctx, photon_context) {
                    // A bit clunky to safely mutate the shared parent of the current ctx
                    let tmp = ctx.parent.as_ref().unwrap().clone();
                    let mut parent = tmp.borrow_mut();
                    parent.insert(extractor.name.as_ref().unwrap(), res);
                }
            }
        }
        for matcher in self.matchers.iter() {
            // Negative XOR matches
            if matcher.negative ^ matcher.matches(&resp, regex_cache, &ctx, photon_context) {
                matches.push(MatchResult {
                    name: matcher.name.clone().unwrap_or("".to_string()),
                    internal: matcher.internal,
                });
            }
        }
    }

    fn execute(
        &self,
        base_url: &str,
        options: &ExecutionOptions,
        curl: &mut Easy2<Collector>,
        regex_cache: &RegexCache,
        parent_ctx: Rc<RefCell<Context>>,
        photon_context: &PhotonContext,
        req_counter: &mut u32,
        cache: &mut Cache,
    ) -> Vec<MatchResult> {
        // TODO: Handle stop at first match logic, currently we stop requesting after we match first http response
        let mut matches = Vec::new();
        let mut ctx = Context {
            variables: FxHashMap::default(),
            parent: Some(parent_ctx),
        };

        if !self.payloads.is_empty() && self.path.len() > 1 {
            println!("paths: {} - {}", self.path.len(), self.payloads.len());
            println!("{:?}", self.payloads);
        }

        // TODO: add upper limit to amount of requests to send, don't want a single template doing hundreds of requests!

        let attack_iter = AttackIterator::new(&self.payloads, self.attack_mode);
        let mut num_reqs = 0;
        for attack_values in attack_iter {
            for (key, value) in attack_values {
                // TODO: for Value::String values, put them through bake_ctx, since some templates contain DSL things in payloads
                ctx.insert(&key, value);
            }

            for (idx, req) in self.path.iter().enumerate() {
                // TODO: possibly inline req.do_request into if let Some statement
                // after function signatures are simplified with ExecutionContext changes
                let maybe_resp = req.do_request(
                    base_url,
                    options,
                    curl,
                    &ctx,
                    photon_context,
                    req_counter,
                    cache,
                );
                if let Some(resp) = maybe_resp {
                    num_reqs += 1;
                    self.handle_response(
                        resp,
                        &mut matches,
                        idx,
                        &mut ctx,
                        regex_cache,
                        photon_context,
                    );

                    // Not the best logic, but should work?
                    match self.matchers_condition {
                        Condition::AND => {
                            if matches.len() == self.matchers.len() {
                                return matches;
                            } else {
                                // Clear because all matchers need to match a single response
                                matches.clear();
                            }
                        }
                        Condition::OR => {
                            if !matches.is_empty() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if num_reqs > 5 {
            println!("Loads of requests: {num_reqs}");
        }

        matches
    }
}

pub struct Collector(pub Vec<u8>, pub Vec<u8>);

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    fn header(&mut self, data: &[u8]) -> bool {
        // Make sure we're appending headers only, curl also gives us the HTTP response code header as well for some reason
        if data.contains(&b':') {
            self.1.extend_from_slice(data);
        }
        true
    }
}

impl Collector {
    pub fn reset(&mut self) {
        self.0.clear();
        self.1.clear();
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
        curl: &mut Easy2<Collector>,
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
