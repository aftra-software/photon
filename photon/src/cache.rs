use std::{
    collections::{HashMap, hash_map::Entry},
    mem::size_of,
};

use bincode::{config, enc::write::SizeWriter};
use lz4::block::{self, CompressionMode};
use regex::Regex;
use rustc_hash::FxHashMap;

use crate::{http::HttpResponse, template::Method};

// Bound table overhead even when most responses are tiny or absent.
const MAX_ENTRIES: usize = 16 * 1024;

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

impl CacheKey {
    fn heap_bytes(&self) -> usize {
        let headers = [&self.headers, &self.extra_headers]
            .into_iter()
            .map(|headers| {
                headers.capacity() * size_of::<String>()
                    + headers.iter().map(String::capacity).sum::<usize>()
            })
            .sum::<usize>();
        headers + self.path.capacity() + self.body.capacity() + self.user_agent.capacity()
    }
}

#[derive(Clone)]
struct CachedResponse {
    data: Option<Box<[u8]>>,
    bytes: usize,
}

#[derive(Clone)]
pub struct Cache {
    inner: HashMap<CacheKey, CachedResponse>,
    capacity: usize,
    used_capacity: usize,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            used_capacity: 0,
            capacity: usize::MAX,
        }
    }

    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        if self.used_capacity > capacity {
            self.reset();
        }
    }

    pub fn reset(&mut self) {
        self.inner = HashMap::new();
        self.used_capacity = 0;
    }

    // The outer option distinguishes a miss from a cached request failure.
    pub fn get(&self, key: &CacheKey) -> Option<Option<HttpResponse>> {
        let entry = self.inner.get(key)?;
        Some(entry.data.as_deref().map(|data| {
            // The cache only stores buffers it encoded and compressed itself.
            let decompressed = block::decompress(data, None).unwrap();
            bincode::decode_from_slice(&decompressed, config::standard())
                .unwrap()
                .0
        }))
    }

    pub fn store(&mut self, key: CacheKey, response: Option<&HttpResponse>) {
        let overhead = size_of::<(CacheKey, CachedResponse)>() + key.heap_bytes();
        let Some(response_budget) = self.capacity.checked_sub(overhead) else {
            return;
        };
        if self.inner.contains_key(&key) {
            return;
        }
        let data = match response {
            Some(response) => {
                let Some(data) = compress_response(response, response_budget) else {
                    return;
                };
                Some(data)
            }
            None => None,
        };
        let bytes = overhead + data.as_deref().map_or(0, <[u8]>::len);

        // Admit only after the whole entry fits by itself, so an oversized
        // response doesn't flush useful entries. Count failures as well.
        while self.inner.len() >= MAX_ENTRIES || self.used_capacity > self.capacity - bytes {
            let (victim, entry) = self
                .inner
                .iter()
                .max_by_key(|(_, entry)| entry.bytes)
                .unwrap();
            let (victim, victim_bytes) = (victim.clone(), entry.bytes);
            self.inner.remove(&victim);
            self.used_capacity -= victim_bytes;
        }
        self.inner.insert(key, CachedResponse { data, bytes });
        self.used_capacity += bytes;
    }
}

fn compress_response(response: &HttpResponse, budget: usize) -> Option<Box<[u8]>> {
    // LZ4 prepends the uncompressed size. Skip encoding responses larger
    // than the budget, even if they might compress enough to fit.
    let prefix = size_of::<u32>();
    if budget <= prefix {
        return None;
    }
    let config = config::standard();
    let mut size = SizeWriter::default();
    bincode::encode_into_writer(response, &mut size, config).ok()?;
    let size = size.bytes_written;
    if size > budget {
        return None;
    }

    let bound = block::compress_bound(size).ok()? + prefix;
    let mut encoded = vec![0; size];
    bincode::encode_into_slice(response, &mut encoded, config).ok()?;
    let mut compressed = vec![0; bound.min(budget)];
    let written = block::compress_to_buffer(
        &encoded,
        Some(CompressionMode::HIGHCOMPRESSION(10)),
        true,
        &mut compressed,
    )
    .ok()?;
    drop(encoded);
    compressed.truncate(written);
    // Discard LZ4 output's spare capacity to retain only the charged bytes.
    Some(compressed.into_boxed_slice())
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

    fn key(index: usize) -> CacheKey {
        CacheKey {
            method: Method::GET,
            headers: vec![],
            path: format!("/{index:05}"),
            body: vec![],
            follow_redirects: false,
            max_redirects: None,
            extra_headers: vec![],
            user_agent: String::new(),
        }
    }

    fn response(body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            req_url: String::new(),
            body,
            headers: vec![],
            status_code: 200,
            duration: 0.0,
        }
    }

    #[test]
    fn boxed_response_buffers_match_cache_memory_accounting() {
        let mut cache = Cache::new();
        cache.set_capacity(1024 * 1024);
        let keys: Vec<_> = (0..20).map(key).collect();
        let response = response(vec![b'x'; 150_000]);

        // These responses only fit together if the cache retains compressed buffers.
        assert!(keys.len() * response.body.len() > cache.capacity);
        for key in &keys {
            cache.store(key.clone(), Some(&response));
        }
        for key in &keys {
            assert_eq!(cache.get(key).unwrap().unwrap().body, response.body);
        }

        let retained_bytes: usize = cache
            .inner
            .iter()
            .map(|(key, entry)| {
                size_of::<(CacheKey, CachedResponse)>()
                    + key.heap_bytes()
                    + entry.data.as_ref().unwrap().len()
            })
            .sum();
        assert_eq!(cache.used_capacity, retained_bytes);
        assert!(retained_bytes <= cache.capacity);
    }

    #[test]
    fn oversized_response_is_not_cached_and_does_not_evict() {
        let mut cache = Cache::new();
        let small = response(vec![b'x'; 25]);
        cache.store(key(0), Some(&small));
        let original_usage = cache.used_capacity;

        let uncompressible = response((0..=255).collect());
        let size = bincode::encode_to_vec(&uncompressible, config::standard())
            .unwrap()
            .len();
        // The byte budget fits the raw encoding but not LZ4's overhead.
        cache.set_capacity(size_of::<(CacheKey, CachedResponse)>() + key(1).heap_bytes() + size);
        cache.store(key(1), Some(&uncompressible));
        assert!(cache.get(&key(1)).is_none());

        // Even a compressible response is skipped if encoding it would
        // allocate scratch space larger than the configured budget.
        cache.store(key(2), Some(&response(vec![b'x'; 4_096])));
        assert!(cache.get(&key(2)).is_none());

        assert_eq!(cache.get(&key(0)).unwrap().unwrap().body, small.body);
        assert_eq!(cache.used_capacity, original_usage);
    }

    #[test]
    fn cache_evicts_an_entry_when_capacity_is_exceeded() {
        let mut cache = Cache::new();
        let response = response(vec![b'x'; 25]);
        cache.store(key(0), Some(&response));
        let entry_size = cache.used_capacity;
        cache.set_capacity(entry_size * 4);

        for index in 1..4 {
            cache.store(key(index), Some(&response));
        }
        assert!((0..4).all(|index| cache.get(&key(index)).is_some()));
        assert_eq!(cache.used_capacity, entry_size * 4);

        cache.store(key(4), Some(&response));

        assert_eq!(cache.get(&key(4)).unwrap().unwrap().body, response.body);
        assert_eq!(cache.inner.len(), 4);
        assert_eq!(cache.used_capacity, entry_size * 4);
        // Equal-sized entries can be evicted in any order.
        assert_eq!(
            (0..4)
                .filter(|&index| cache.get(&key(index)).is_some())
                .count(),
            3
        );
    }

    #[test]
    fn failure_entries_charge_for_request_keys() {
        let mut cache = Cache::new();
        cache.store(key(0), None);
        let entry_size = cache.used_capacity;
        assert!(matches!(cache.get(&key(0)), Some(None)));
        cache.set_capacity(entry_size);

        let large_key = CacheKey {
            headers: vec!["X-Fixture: ".to_string() + &"x".repeat(4_096)],
            ..key(1)
        };
        cache.store(large_key.clone(), None);
        assert!(cache.get(&large_key).is_none());
        assert!(matches!(cache.get(&key(0)), Some(None)));

        cache.store(key(2), None);
        assert!(cache.get(&key(0)).is_none());
        assert!(matches!(cache.get(&key(2)), Some(None)));
        assert_eq!(cache.used_capacity, entry_size);
    }

    #[test]
    fn entry_count_is_bounded_even_with_an_unlimited_byte_budget() {
        let mut cache = Cache::new();
        for index in 0..=MAX_ENTRIES {
            cache.store(key(index), None);
        }

        assert_eq!(cache.inner.len(), MAX_ENTRIES);
        assert!(matches!(cache.get(&key(MAX_ENTRIES)), Some(None)));
    }

    #[test]
    fn reset_releases_the_budget_and_zero_disables_caching() {
        let mut cache = Cache::new();
        cache.store(key(0), None);
        let entry_size = cache.used_capacity;
        cache.set_capacity(entry_size);
        cache.reset();
        assert!(cache.get(&key(0)).is_none());

        cache.store(key(1), None);
        assert!(matches!(cache.get(&key(1)), Some(None)));
        assert_eq!(cache.used_capacity, entry_size);

        cache.set_capacity(0);
        assert!(cache.get(&key(1)).is_none());
        cache.store(key(2), None);
        assert!(cache.get(&key(2)).is_none());
        assert_eq!(cache.used_capacity, 0);
    }
}
