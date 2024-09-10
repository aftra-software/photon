use crate::{
    cache::Cache,
    dsl::{CompiledExpression, DSLStack, Value},
    http::{HttpReq, HttpResponse},
};
use md5::{Digest, Md5};
use regex::{Regex, RegexSet};
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
pub enum Method {
    GET,
    POST,
    HEAD,
    PATCH,
    DELETE,
    OPTIONS,
}

#[derive(Debug)]
pub enum RegexType {
    PatternList(Vec<Regex>),
    Set(RegexSet),
}

#[derive(Debug)]
pub enum MatcherType {
    Word(Vec<String>),
    DSL(Vec<CompiledExpression>),
    Regex(RegexType),
    Status(Vec<u8>),
}

#[derive(Debug, Clone, Copy)]
pub enum ResponsePart {
    Body,
    Raw,
    Header,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug)]
pub struct Context {
    pub variables: FxHashMap<String, Value>,
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
    pub fn matches<F>(
        &self,
        data: &HttpResponse,
        functions: &FxHashMap<String, F>,
        context: &Context,
    ) -> bool
    where
        F: Fn(&mut DSLStack) -> Result<(), ()>,
    {
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
                if self.condition == Condition::OR {
                    dsls.iter().any(|expr| {
                        let res = expr.execute(
                            &context.variables,
                            &functions,
                        );
                        res.is_ok() && (res.unwrap() == Value::Boolean(true))
                    })
                } else {
                    dsls.iter().all(|expr| {
                        let res = expr.execute(
                            &context.variables,
                            &functions,
                        );
                        res.is_ok() && (res.unwrap() == Value::Boolean(true))
                    })
                }
            }
            // TODO: Make sure Condition is taken into consideration
            MatcherType::Regex(regexes) => match regexes {
                RegexType::PatternList(patterns) => {
                    patterns.iter().all(|pattern| pattern.is_match(&data))
                }
                RegexType::Set(patterns) => patterns.is_match(&data),
            },
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
    pub fn matches_status(&self, status: u8) -> bool {
        match &self.r#type {
            MatcherType::Status(statuses) => statuses.iter().any(|s| *s == status),
            _ => panic!("Cannot match status when type != MatcherType::Status"),
        }
    }
}

impl HttpRequest {
    pub fn execute<F>(
        &self,
        base_url: &str,
        agent: &Agent,
        functions: &FxHashMap<String, F>,
        req_counter: &mut u32,
        cache: &mut Cache,
    ) -> Vec<MatchResult>
    where
        F: Fn(&mut DSLStack) -> Result<(), ()>,
    {
        // TODO: Handle stop at first match logic, currently we stop requesting after we match first http response
        let mut matches = Vec::new();
        let mut ctx = Context {
            variables: FxHashMap::default(),
        };

        for (idx, req) in self.path.iter().enumerate() {
            let maybe_resp = req.do_request(base_url, agent, req_counter, cache);
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
                    if matcher.negative ^ matcher.matches(&resp, functions, &ctx) {
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

impl Template {
    pub fn execute<F>(
        &self,
        base_url: &str,
        agent: &Agent,
        functions: &FxHashMap<String, F>,
        req_counter: &mut u32,
        cache: &mut Cache,
    ) where
        F: Fn(&mut DSLStack) -> Result<(), ()>,
    {
        for http in self.http.iter() {
            let match_results = http.execute(base_url, agent, functions, req_counter, cache);
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
