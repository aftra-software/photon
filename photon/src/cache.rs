use std::{
    collections::{HashMap, hash_map::Entry},
    usize,
};

use bincode::config;
use lz4::block::{self, CompressionMode};
use regex::Regex;
use rustc_hash::FxHashMap;

use crate::{http::HttpResponse, template::Method};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
// The complete rendered request state that can affect the response.
pub struct CacheKey {
    pub method: Method,
    pub headers: Vec<String>,
    pub path: String,
    pub body: Vec<u8>,
    pub follow_redirects: bool,
    pub max_redirects: Option<u32>,
    pub extra_headers: Vec<String>,
    pub user_agent: String,
}

#[derive(Clone)]
pub struct Cache {
    inner: HashMap<CacheKey, Option<Vec<u8>>>,
    current_tokens: HashMap<CacheKey, u16>,
    tokens: HashMap<CacheKey, u16>,
    capacity: usize,
    used_capacity: usize,
}

impl Cache {
    pub fn new(tokens: HashMap<CacheKey, u16>) -> Self {
        let mut new = Self {
            inner: HashMap::new(),
            current_tokens: HashMap::new(),
            tokens,
            used_capacity: 0,
            capacity: usize::MAX,
        };
        new.reset();

        new
    }

    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
    }

    #[allow(unused)]
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

    fn increase_usage_and_evict_if_needed(&mut self, amount: usize) {
        while self.used_capacity > 0 && amount > self.capacity.saturating_sub(self.used_capacity) {
            let biggest_entry = self
                .inner
                .iter()
                .filter_map(|(key, value)| value.as_ref().map(|data| (key, data.len())))
                .max_by_key(|(_, size)| *size)
                .map(|(key, size)| (key.clone(), size));

            if let Some((key, size)) = biggest_entry {
                self.inner.remove(&key);
                self.used_capacity -= size;
            }
        }
        self.used_capacity += amount;
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

            self.increase_usage_and_evict_if_needed(compressed.len());
            self.inner.insert(key.clone(), Some(compressed));
        } else {
            self.inner.insert(key.clone(), None);
        }
    }

    pub fn can_cache(&self, _key: &CacheKey) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_response_evicts_all_previous_entries() {
        let mut cache = Cache::new(HashMap::new());
        let keys: Vec<_> = (0..4)
            .map(|i| CacheKey {
                method: Method::GET,
                headers: vec![],
                path: format!("/{i}"),
                body: vec![],
                follow_redirects: false,
                max_redirects: None,
                extra_headers: vec![],
                user_agent: String::new(),
            })
            .collect();
        let small_response = HttpResponse {
            req_url: String::new(),
            body: vec![b'x'; 25],
            headers: vec![],
            status_code: 200,
            duration: 0.0,
        };

        cache.store(&keys[0], Some(small_response.clone()));
        let small_size = cache.inner[&keys[0]].as_ref().unwrap().len();
        cache.set_capacity(small_size * 3);
        for key in &keys[1..3] {
            cache.store(key, Some(small_response.clone()));
        }
        assert!(keys[..3].iter().all(|key| cache.contains(key)));
        assert_eq!(cache.used_capacity, cache.capacity);

        let large_response = HttpResponse {
            // Distinct bytes keep this larger than the limit after compression.
            body: (0..=255).collect(),
            ..small_response
        };
        cache.store(&keys[3], Some(large_response.clone()));

        let large_size = cache.inner[&keys[3]].as_ref().unwrap().len();
        assert!(large_size > cache.capacity);
        assert!(keys[..3].iter().all(|key| !cache.contains(key)));
        assert_eq!(cache.inner.len(), 1);
        assert_eq!(cache.used_capacity, large_size);
        assert_eq!(cache.get(&keys[3]).unwrap().body, large_response.body);
    }

    #[test]
    fn cache_evicts_an_entry_when_capacity_is_exceeded() {
        let mut cache = Cache::new(HashMap::new());
        let keys: Vec<_> = (0..5)
            .map(|i| CacheKey {
                method: Method::GET,
                headers: vec![],
                path: format!("/{i}"),
                body: vec![],
                follow_redirects: false,
                max_redirects: None,
                extra_headers: vec![],
                user_agent: String::new(),
            })
            .collect();
        let response = HttpResponse {
            req_url: String::new(),
            body: vec![b'x'; 25],
            headers: vec![],
            status_code: 200,
            duration: 0.0,
        };

        cache.store(&keys[0], Some(response.clone()));
        // Capacity counts compressed responses, rather than just their bodies.
        let entry_size = cache.inner[&keys[0]].as_ref().unwrap().len();
        cache.set_capacity(entry_size * 4);

        for key in &keys[1..4] {
            cache.store(key, Some(response.clone()));
        }
        assert!(keys[..4].iter().all(|key| cache.contains(key)));
        assert_eq!(cache.used_capacity, entry_size * 4);

        cache.store(&keys[4], Some(response));

        assert!(cache.contains(&keys[4]));
        assert_eq!(cache.inner.len(), 4);
        assert_eq!(cache.used_capacity, entry_size * 4);
        // Equal-sized entries can be evicted in any order.
        assert_eq!(
            keys[..4].iter().filter(|key| cache.contains(key)).count(),
            3
        );
    }
}
