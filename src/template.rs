use core::str;
use std::{rc::Rc, sync::Mutex};

use crate::{
    cache::{Cache, RegexCache},
    dsl::{CompiledExpression, Value, GLOBAL_FUNCTIONS},
    http::{HttpReq, HttpResponse},
};
use curl::easy::{Easy2, Handler, List, WriteError};
use rustc_hash::{FxHashMap, FxHashSet};
use ureq::Agent;

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

#[derive(Debug)]
pub enum MatcherType {
    Word(Vec<String>),
    DSL(Vec<CompiledExpression>),
    Regex(Vec<u32>), // indicies into RegexCache
    Status(Vec<u32>),
}

#[derive(Debug, Clone, Copy)]
pub enum ResponsePart {
    Body,
    Raw,
    Header,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum Condition {
    AND,
    OR,
}

#[derive(Debug)]
pub struct Info {
    pub name: String,
    pub author: String,
    pub description: String,
    pub severity: Severity,
    pub reference: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug)]
pub struct Matcher {
    pub r#type: MatcherType,
    pub name: Option<String>,
    pub negative: bool,
    pub internal: bool, // Used for workflows, matches, but does not print
    pub part: ResponsePart,
    pub condition: Condition,
}

#[derive(Debug)]
pub struct HttpRequest {
    pub matchers: Vec<Matcher>,
    pub matchers_condition: Condition,
    pub path: Vec<HttpReq>,
    pub headers: Vec<(String, String)>, // TODO: use headers
}

// TODO: Maybe make this implement HashMap or something to not create a new temporary flattened each usage.
#[derive(Debug)]
pub struct Context {
    pub variables: FxHashMap<String, Value>,
    pub parent: Option<Rc<Mutex<Context>>>,
}

impl Context {
    // Returns a variable mapping, where the parent's variables have lower priority
    // Than the current context's variables
    // TODO: Probably incredibly slow
    pub fn flatten_variables(&self) -> FxHashMap<String, Value> {
        if self.parent.is_some() {
            let mut variables = self
                .parent
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .flatten_variables();
            for (k, v) in self.variables.iter() {
                variables.insert(k.clone(), v.clone());
            }
            variables
        } else {
            self.variables.clone()
        }
    }
}

#[derive(Debug)]
pub struct Template {
    pub id: String,
    pub info: Info,
    pub http: Vec<HttpRequest>,
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

impl Matcher {
    pub fn matches(
        &self,
        data: &HttpResponse,
        regex_cache: &RegexCache,
        context: &Context,
    ) -> bool {
        if let MatcherType::Status(_) = self.r#type {
            return self.matches_status(data.status_code);
        }

        let data = match self.part {
            ResponsePart::All => {
                // TODO: Actually return proper All
                let mut parts = vec![];
                data.headers
                    .iter()
                    .for_each(|(k, v)| parts.push(format!("{}: {}\n", k, v)));
                parts.push(data.body.clone());
                parts.concat()
            }
            ResponsePart::Body => data.body.clone(),
            ResponsePart::Header => data
                .headers
                .iter()
                .map(|(k, v)| format!("{}: {}\n", k, v))
                .collect::<Vec<String>>()
                .concat(),
            ResponsePart::Raw => {
                // TODO: Actually return Raw
                let mut parts = vec![];
                data.headers
                    .iter()
                    .for_each(|(k, v)| parts.push(format!("{}: {}\n", k, v)));
                parts.push(data.body.clone());
                parts.concat()
            }
        };
        match &self.r#type {
            MatcherType::DSL(dsls) => {
                let vars = context.flatten_variables();
                if self.condition == Condition::OR {
                    dsls.iter().any(|expr| {
                        let res = expr.execute(&vars, GLOBAL_FUNCTIONS.get().unwrap());
                        res.is_ok() && (res.unwrap() == Value::Boolean(true))
                    })
                } else {
                    dsls.iter().all(|expr| {
                        let res = expr.execute(&vars, GLOBAL_FUNCTIONS.get().unwrap());
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
            _ => false,
        }
    }
    pub fn matches_status(&self, status: u32) -> bool {
        match &self.r#type {
            MatcherType::Status(statuses) => statuses.iter().any(|s| *s == status),
            _ => panic!("Cannot match status when type != MatcherType::Status"),
        }
    }
}

impl HttpRequest {
    pub fn execute(
        &self,
        base_url: &str,
        agent: &Agent,
        curl: &mut Easy2<Collector>,
        regex_cache: &RegexCache,
        parent_ctx: Rc<Mutex<Context>>,
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
            let maybe_resp = req.do_request(base_url, agent, curl, &ctx, req_counter, cache);
            if let Some(resp) = maybe_resp {
                ctx.variables.insert(
                    format!("body_{}", idx + 1),
                    Value::String(resp.body.clone()),
                );
                ctx.variables
                    .insert("body".to_string(), Value::String(resp.body.clone()));
                ctx.variables.insert(
                    format!("status_code_{}", idx + 1),
                    Value::Int(resp.status_code as i64),
                );
                ctx.variables.insert(
                    "status_code".to_string(),
                    Value::Int(resp.status_code as i64),
                );
                ctx.variables.insert(
                    "header".to_string(),
                    Value::String(
                        resp.headers
                            .iter()
                            .fold(String::with_capacity(512), |acc, hed| {
                                acc + &format!("{}: {}", hed.0, hed.1) + "\n"
                            })
                            .trim()
                            .to_string(),
                    ),
                );
                for matcher in self.matchers.iter() {
                    // Negative XOR matches
                    if matcher.negative ^ matcher.matches(&resp, regex_cache, &ctx) {
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

pub struct Collector(pub Vec<u8>, pub Vec<String>);

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    fn header(&mut self, data: &[u8]) -> bool {
        self.1.push(String::from_utf8_lossy(data).to_string());
        true
    }
}

impl Template {
    pub fn execute(
        &self,
        base_url: &str,
        agent: &Agent,
        curl: &mut Easy2<Collector>,
        parent_ctx: Rc<Mutex<Context>>,
        req_counter: &mut u32,
        cache: &mut Cache,
        regex_cache: &RegexCache,
    ) {
        let ctx = Rc::from(Mutex::from(Context {
            variables: FxHashMap::default(),
            parent: Some(parent_ctx),
        }));
        for http in self.http.iter() {
            let match_results = http.execute(
                base_url,
                agent,
                curl,
                regex_cache,
                ctx.clone(),
                req_counter,
                cache,
            );
            if !match_results.is_empty() {
                // Stupid string printing, for the cases where we have templates like
                // missing-header:x-iframe-whatever
                // missing-header:content-security-policy
                // And want to display the different cases that were matched
                let mut unique_names = FxHashSet::default();
                for matched in match_results.iter() {
                    if !matched.internal {
                        unique_names.insert(matched.name.clone());
                    }
                }
                for name in unique_names {
                    if name.is_empty() {
                        println!(
                            "Matched: [{}] {}",
                            self.info.severity.colored_string(),
                            self.id
                        );
                    } else {
                        println!(
                            "Matched: [{}] {}:{}",
                            self.info.severity.colored_string(),
                            self.id,
                            name
                        );
                    }
                }
            }
        }
    }
}
