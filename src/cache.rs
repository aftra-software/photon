use std::collections::HashMap;

use regex::Regex;
use rustc_hash::FxHashMap;

use crate::{http::HttpResponse, template::Method};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey(pub Method, pub String);

pub struct Cache {
    inner: HashMap<CacheKey, Option<HttpResponse>>,
    current_tokens: HashMap<CacheKey, u16>,
    tokens: HashMap<CacheKey, u16>,
}

impl Cache {
    pub fn new(tokens: HashMap<CacheKey, u16>) -> Self {
        let mut new = Self {
            inner: HashMap::new(),
            current_tokens: HashMap::new(),
            tokens,
        };
        new.reset();

        new
    }

    fn decrease_token(&mut self, key: &CacheKey) {
        let tokens_left = self.current_tokens.get_mut(key).unwrap();
        if *tokens_left == 1 {
            // Final token, we know this cache key will never be accessed again until we reset
            self.current_tokens.remove(key);
            self.inner.remove(key);

            // Clear out freed data so that other threads/whatever can utilize it
            self.current_tokens.shrink_to_fit();
            self.inner.shrink_to_fit();
        } else {
            *tokens_left -= 1;
        }
    }

    pub fn reset(&mut self) {
        self.inner.clear();
        self.current_tokens = self.tokens.clone();
    }

    pub fn get(&mut self, key: &CacheKey) -> Option<HttpResponse> {
        let ret = self.inner.get(key).unwrap().clone();
        self.decrease_token(key);
        ret
    }

    pub fn contains(&self, key: &CacheKey) -> bool {
        self.inner.contains_key(key)
    }

    pub fn store(&mut self, key: &CacheKey, value: Option<HttpResponse>) {
        self.inner.insert(key.clone(), value);
    }

    pub fn can_cache(&self, key: &CacheKey) -> bool {
        self.current_tokens.contains_key(key)
    }
}

pub struct RegexCache {
    patterns: Vec<Regex>,
    known: FxHashMap<String, u32>,
}

impl RegexCache {
    pub fn new() -> Self {
        Self {
            patterns: vec![],
            known: FxHashMap::default(),
        }
    }

    pub fn insert(&mut self, patt: &str) -> Result<u32, regex::Error> {
        if self.known.contains_key(&patt.to_string()) {
            Ok(*self.known.get(&patt.to_string()).unwrap())
        } else {
            let idx = self.patterns.len();
            self.known.insert(patt.to_string(), idx as u32);
            self.patterns.push(Regex::new(patt)?);
            Ok(idx as u32)
        }
    }

    // Panics if the given idx is not valid
    pub fn matches(&self, idx: u32, data: &str) -> bool {
        self.patterns[idx as usize].is_match(data)
    }

    pub fn finalize(&mut self) {
        // Just about clear the hashmap, without removing it, because its easier to implement
        self.known.clear();
        self.known.shrink_to_fit();
    }
}
