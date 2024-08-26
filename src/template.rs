use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use crate::http::{HttpReq, HttpResponse};
use regex::Regex;

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Unknown,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn to_string(&self) -> String {
        match self {
            Self::Critical => "critical".to_string(),
            Self::High => "high".to_string(),
            Self::Medium => "medium".to_string(),
            Self::Low => "low".to_string(),
            Self::Info => "info".to_string(),
            Self::Unknown => "unknown".to_string(),
        }
    }
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
pub enum MatcherType {
    Word(Vec<String>),
    DSL(Vec<String>),
    Regex(Vec<String>),
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
    pub negative: bool,
    pub internal: bool,
    pub part: ResponsePart,
    pub condition: Condition,
}

pub static REGEX_CACHE: OnceLock<Mutex<HashMap<String, Regex>>> = OnceLock::new();

fn get_or_init_regex<'a>(key: &String, cache: &'a mut HashMap<String, Regex>) -> &'a Regex {
    if !cache.contains_key(key) {
        cache.insert(key.clone(), Regex::new(key).unwrap());
    }
    cache.get(key).unwrap()
}

impl Matcher {
    pub fn matches(&self, data: &HttpResponse) -> bool {
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
                .map(|(k, v)| format!("{}: {}\n", k, v).into())
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
            MatcherType::DSL(_) => false,
            MatcherType::Regex(regexes) => {
                let c = REGEX_CACHE.get().unwrap();
                let mut cache = c.lock().unwrap();
                if self.condition == Condition::OR {
                    regexes
                        .iter()
                        .any(|pattern| get_or_init_regex(pattern, &mut cache).is_match(&data))
                } else {
                    regexes
                        .iter()
                        .all(|pattern| get_or_init_regex(pattern, &mut cache).is_match(&data))
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
    pub fn matches_status(&self, status: u8) -> bool {
        match &self.r#type {
            MatcherType::Status(statuses) => statuses.iter().any(|s| *s == status),
            _ => panic!("Cannot match status when type != MatcherType::Status"),
        }
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    pub matchers: Vec<Matcher>,
    pub matchers_condition: Condition,
    pub path: Vec<HttpReq>,
}

#[derive(Debug)]
pub struct Template {
    pub id: String,
    pub info: Info,
    pub http: Vec<HttpRequest>,
}
