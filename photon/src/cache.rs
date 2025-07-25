use std::collections::{hash_map::Entry, HashMap};

use bincode::config;
use lz4::block::{self, CompressionMode};
use regex::Regex;
use rustc_hash::FxHashMap;

use crate::{http::HttpResponse, template::Method};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
// (Method, Headers, Path)
pub struct CacheKey(pub Method, pub Vec<String>, pub String);

#[derive(Clone)]
pub struct Cache {
    inner: HashMap<CacheKey, Option<Vec<u8>>>,
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
        // XXX: Tokens are currently used to determine if its likely a request
        // repeated across multiple templates, thus we don't decrease currently
        //self.decrease_token(key);
        if let Some(data) = ret {
            // Unwraps below should be 100% safe, since both bincode and compressed data are created by `store` function below.
            let decompressed = block::decompress(&data, None).unwrap();
            let (resp, _) = bincode::decode_from_slice(&decompressed, config::standard()).unwrap();
            Some(resp)
        } else {
            None
        }
    }

    pub fn contains(&self, key: &CacheKey) -> bool {
        self.inner.contains_key(key)
    }

    pub fn store(&mut self, key: &CacheKey, value: Option<HttpResponse>) {
        if let Some(data) = value {
            let encoded = bincode::encode_to_vec(data.clone(), config::standard()).unwrap();
            // Compression level 10 is used since `store` isn't called all that often, so spending a bit of time to save memory is worth it.
            let compressed =
                block::compress(&encoded, Some(CompressionMode::HIGHCOMPRESSION(10)), true)
                    .unwrap();
            self.inner.insert(key.clone(), Some(compressed));
        } else {
            self.inner.insert(key.clone(), None);
        }
    }

    pub fn can_cache(&self, key: &CacheKey) -> bool {
        //self.current_tokens.contains_key(key)

        // XXX: Always return true for now, while the caching implementation caches all requests
        true
    }
}

#[derive(Clone)]
pub struct RegexCache {
    patterns: Vec<Regex>,
    known: FxHashMap<String, u32>,
}

impl Default for RegexCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexCache {
    pub fn new() -> Self {
        Self {
            patterns: vec![],
            known: FxHashMap::default(),
        }
    }

    pub fn insert(&mut self, patt: &str) -> Result<u32, regex::Error> {
        if let Entry::Vacant(e) = self.known.entry(patt.to_string()) {
            // Make sure to compile before modifying Cache state, so we don't pollute with invalid patterns
            let compiled = Regex::new(patt)?;

            let idx = self.patterns.len();
            e.insert(idx as u32);
            self.patterns.push(compiled);
            Ok(idx as u32)
        } else {
            Ok(*self.known.get(patt).unwrap())
        }
    }

    // Panics if the given idx is not valid
    pub fn matches(&self, idx: u32, data: &str) -> bool {
        self.patterns[idx as usize].is_match(data)
    }

    // Panics if the given idx is not valid, returns n-th group match for given pattern
    pub fn match_group(&self, idx: u32, data: &str, group: usize) -> Option<String> {
        Some(
            self.patterns[idx as usize]
                .captures(data)?
                .get(group)?
                .as_str()
                .to_string(),
        )
    }

    pub fn finalize(&mut self) {
        // Just about clear the hashmap, without removing it, because its easier to implement
        self.known.clear();
        self.known.shrink_to_fit();
    }
}
