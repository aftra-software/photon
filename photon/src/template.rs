use core::str;
use std::{rc::Rc, sync::Mutex};

use crate::{
    cache::{Cache, RegexCache},
    get_config,
    http::{HttpReq, HttpResponse},
    template_executor::ExecutionOptions,
    PhotonContext,
};
use curl::easy::{Easy2, Handler, WriteError};
use photon_dsl::dsl::{CompiledExpression, Value, VariableContainer};
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
    Kval(Vec<String>)
}

#[derive(Debug, Clone, Copy)]
pub enum ExtractorPart {
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

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub extractors: Vec<Extractor>,
    pub matchers: Vec<Matcher>,
    pub matchers_condition: Condition,
    pub path: Vec<HttpReq>,
}

#[derive(Debug)]
pub struct Context {
    pub variables: FxHashMap<String, Value>,
    pub parent: Option<Rc<Mutex<Context>>>,
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
        if self.parent.is_some() {
            self.variables.contains_key(key)
                || self
                    .parent
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .contains_key(key)
        } else {
            self.variables.contains_key(key)
        }
    }

    fn get(&self, key: &str) -> Option<Value> {
        if self.contains_key(key) {
            if self.variables.contains_key(key) {
                Some(self.variables.get(key).unwrap().clone())
            } else {
                Some(
                    self.parent
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .get(key)
                        .unwrap(),
                )
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
}

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
        ExtractorPart::Header => response_to_string(data, ResponsePart::Header),

        // Concatenated all cookie headers into a single string
        ExtractorPart::Cookie => {
            data
                .headers
                .iter()
                .filter(|(key, val)| key.to_lowercase() == "cookie")
                .map(|(key, value)| format!("{value}\n"))
                .collect::<Vec<String>>()
                .concat()
        },
    }
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
                    words.iter().any(|needle| data.contains(needle))
                } else {
                    words.iter().all(|needle| data.contains(needle))
                }
            }
            MatcherType::Status(_) => false,
        }
    }

    fn matches_status(&self, status: u32) -> bool {
        match &self.r#type {
            MatcherType::Status(statuses) => statuses.iter().any(|s| *s == status),
            _ => unreachable!("Cannot match status when type != MatcherType::Status"),
        }
    }
}

impl Extractor {
    pub fn extract(
        &self,
        data: &HttpResponse,
        regex_cache: &RegexCache,
        context: &Context,
        photon_context: &PhotonContext,
    ) -> Option<Value> {
        match self.r#type {
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
                            regex_cache.match_group(*pattern, &data, self.group.unwrap_or(0) as usize)
                        })
                        .next()
                        .map(Value::String),
                    MatcherType::Word(_) => {
                        debug!("Extractor does not support Word matching");
                        None
                    }
                    MatcherType::Status(_) => None,
                }
            },
            ExtractorType::Kval(fields) => {
                //TODO: figure this shit out
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

impl HttpRequest {
    pub fn execute(
        &self,
        base_url: &str,
        options: &ExecutionOptions,
        curl: &mut Easy2<Collector>,
        regex_cache: &RegexCache,
        parent_ctx: Rc<Mutex<Context>>,
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

        for (idx, req) in self.path.iter().enumerate() {
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
                            acc + &format!("{}: {}", hed.0, hed.1) + "\n"
                        })
                        .trim(),
                );
                for extractor in self.extractors.iter() {
                    if extractor.name.is_some() {
                        if let Some(res) =
                            extractor.extract(&resp, regex_cache, &ctx, photon_context)
                        {
                            // A bit clunky to safely mutate the shared parent of the current ctx
                            let tmp = ctx.parent.as_ref().unwrap().clone();
                            let mut locked_parent = tmp.lock().unwrap();
                            locked_parent.insert(extractor.name.as_ref().unwrap(), res);
                        }
                    }
                }
                for matcher in self.matchers.iter() {
                    // Negative XOR matches
                    if matcher.negative ^ matcher.matches(&resp, regex_cache, &ctx, photon_context)
                    {
                        matches.push(MatchResult {
                            name: matcher.name.clone().unwrap_or("".to_string()),
                            internal: matcher.internal,
                        });
                    }
                }
            }

            // Not the best logic, but should work?
            match self.matchers_condition {
                Condition::AND => {
                    if matches.len() == self.matchers.len() {
                        return matches;
                    } else {
                        // Clear because we want all matches to appear for 1 response
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
    // There's a lot of stuff we need to pass from a higher context into the templates & requests
    pub fn execute<K, C>(
        &self,
        base_url: &str,
        options: &ExecutionOptions,
        curl: &mut Easy2<Collector>,
        parent_ctx: Rc<Mutex<Context>>,
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
        let ctx = Rc::from(Mutex::from(Context {
            variables: FxHashMap::from_iter(self.variables.iter().cloned()),
            parent: Some(parent_ctx),
        }));
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
                    if name.is_empty() {
                        if callback.is_some() {
                            callback.as_ref().unwrap()(self, None);
                        }
                    } else if callback.is_some() {
                        callback.as_ref().unwrap()(self, Some(name));
                    }
                }
            }
        }
        true
    }
}
