use core::str;
use std::{
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use curl::easy::{Easy2, List};
use curl_sys::CURLOPT_CUSTOMREQUEST;
use httparse::Status;
use regex::Regex;

use crate::{
    cache::{Cache, CacheKey},
    dsl::{Value, GLOBAL_FUNCTIONS},
    parser::compile_expression,
    template::{Collector, Context, Method},
    CONFIG,
};

pub static BRACKET_PATTERN: OnceLock<Mutex<Regex>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub status_code: u32,
    pub duration: f32,
}

#[derive(Debug)]
pub struct HttpReq {
    pub method: Method,
    pub headers: Vec<String>,
    pub path: String,
    pub body: String,
    pub raw: String,
}

fn bake_ctx(inp: &String, ctx: &Context) -> Option<String> {
    let mut baked = inp.clone();
    let flattened = ctx.flatten_variables();
    loop {
        let tmp = baked.clone();
        let matches: Vec<regex::Match<'_>> = BRACKET_PATTERN
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .find_iter(tmp.as_str())
            .collect();

        let mut updated = 0;
        for mat in matches.iter() {
            let compiled = compile_expression(&mat.as_str()[2..mat.len() - 2]);
            if let Ok(expr) = compiled {
                let res = expr.execute(&flattened, GLOBAL_FUNCTIONS.get().unwrap());
                if let Ok(Value::String(ret)) = res {
                    baked = baked.replace(mat.as_str(), &ret);
                    updated += 1;
                }
            }
        }
        // End condition, when no more patterns match/can be replaced
        if updated == 0 {
            if matches.len() > 0 {
                if CONFIG.get().unwrap().verbose {
                    // TODO: Better message?
                    eprintln!("Skipping request, {} missing parameters", matches.len());
                }
                return None; // There's more to match that we couldn't match, invalid request
            }
            break;
        }
    }

    Some(baked)
}

fn parse_headers(contents: &Vec<u8>) -> Vec<(String, String)> {
    String::from_utf8_lossy(&contents)
        .split('\n')
        .filter(|chunk| chunk.len() > 0)
        .map(|a| {
            if let Some((key, value)) = a.split_once(':') {
                (key.to_string(), value.trim().to_string())
            } else {
                // If this happens we're doing something wrong, just panic at that point
                println!("Offending header: {a}");
                panic!("Error splitting header, shouldn't happen ever! If you see this report as bug!");
            }
        })
        .collect()
}

impl HttpReq {
    /// Bakes the request with variables from `ctx`, returning the populated request path.
    pub fn bake(&self, ctx: &Context) -> Option<String> {
        bake_ctx(&self.path, ctx)
    }

    pub fn bake_raw(&self, ctx: &Context) -> Option<String> {
        bake_ctx(&self.raw, ctx)
    }

    fn internal_request(
        &self,
        path: &str,
        curl: &mut Easy2<Collector>,
        req_counter: &mut u32,
    ) -> Option<HttpResponse> {
        let stopwatch = Instant::now();

        // TODO: CURL Error Handling

        // Reset CURL context from last request
        curl.get_mut().reset(); // Reset collector
        curl.reset(); // Reset handle to initial state, keeping connections open
        curl.cookie_list("ALL").unwrap(); // Reset stored cookies
        curl.useragent("Photon/0.1").unwrap(); // TODO: Allow customization

        // Setup CURL context for this request
        curl.path_as_is(true).unwrap();
        curl.timeout(Duration::from_secs(10)).unwrap(); // Max 10 seconds for entire request, TODO: Make configurable
        curl.url(path).unwrap();

        if self.body.len() > 0 {
            curl.post_fields_copy(self.body.as_bytes()).unwrap();
        }

        match self.method {
            Method::GET => {
                curl.get(true).unwrap();
            }
            Method::POST => {
                curl.post(true).unwrap();
            }
            // HTTP Methods outside of GET aren't implemented for CURL's Easy wrapper
            // So we interact with the raw curl handle manually, and set the request type to "custom"
            Method::DELETE => unsafe {
                curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "DELETE");
            },
            Method::HEAD => unsafe {
                curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "HEAD");
            },
            Method::OPTIONS => unsafe {
                curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "OPTIONS");
            },
            Method::PATCH => unsafe {
                curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "PATCH");
            },
        }

        let mut headers = List::new();
        for header in self.headers.iter() {
            headers.append(header).unwrap();
        }
        curl.http_headers(headers).unwrap();

        // Perform CURL request
        if let Err(err) = curl.perform() {
            if CONFIG.get().unwrap().verbose {
                println!("Error requesting URL: {}", path);
                println!("err: {}", err);
            }
            // Failed, no resp
            return None;
        }
        *req_counter += 1;

        let duration = stopwatch.elapsed().as_secs_f32();

        let contents = curl.get_ref();
        let body = String::from_utf8_lossy(&contents.0);
        let headers = parse_headers(&contents.1);

        let resp = HttpResponse {
            body: body.to_string(),
            status_code: curl.response_code().unwrap(),
            duration,
            headers,
        };

        Some(resp)
    }

    fn raw_request(
        &self,
        base_url: &str,
        ctx: &Context,
        curl: &mut Easy2<Collector>,
        req_counter: &mut u32,
    ) -> Option<HttpResponse> {
        let mut raw_data = self.bake_raw(ctx)?;
        if let Value::String(hostname) = ctx.flatten_variables().get("Hostname").unwrap() {
            if !raw_data.contains(hostname) {
                // We don't want to do this request, expected hostname is missing
                return None;
            }
        }

        // Makes parsing that much more reliable, since HTTP requests end with two newlines
        while !raw_data.ends_with("\n\n") {
            raw_data.push('\n');
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let parsed = req.parse(raw_data.as_bytes());
        if let Err(err) = parsed {
            if CONFIG.get().unwrap().verbose {
                eprintln!(
                    "Error parsing raw request: {} - request: '{}'",
                    err, raw_data
                );
            }
            return None;
        }

        let len = match parsed.unwrap() {
            Status::Complete(len) => len,
            Status::Partial => raw_data.len(), // Shouldn't happen, but if it does, we should still have parsed the entire request
        };

        let body = &raw_data[len..];

        if let None = req.path {
            if CONFIG.get().unwrap().verbose {
                eprintln!("Error: Raw request parsed 'path' missing");
            }
            return None;
        }

        let stopwatch = Instant::now();

        // TODO: Merge with CURL handling code above, since it's nearly identical

        // Reset CURL context from last request
        curl.get_mut().reset(); // Reset collector
        curl.reset(); // Reset handle to initial state, keeping connections open
        curl.cookie_list("ALL").unwrap(); // Reset stored cookies
        curl.useragent("Photon/0.1").unwrap(); // TODO: Allow customization

        // Setup CURL context for this request
        curl.path_as_is(true).unwrap();
        curl.timeout(Duration::from_secs(10)).unwrap(); // Max 10 seconds for entire request, TODO: Make configurable
        curl.url(&format!("{}{}", base_url, req.path.unwrap()))
            .unwrap();
        
        if body.len() > 0 {
            curl.post_fields_copy(body.as_bytes()).unwrap();
        }

        match self.method {
            Method::GET => {
                curl.get(true).unwrap();
            }
            Method::POST => {
                curl.post(true).unwrap();
            }
            // HTTP Methods outside of GET aren't implemented for CURL's Easy wrapper
            // So we interact with the raw curl handle manually, and set the request type to "custom"
            Method::DELETE => unsafe {
                curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "DELETE");
            },
            Method::HEAD => unsafe {
                curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "HEAD");
            },
            Method::OPTIONS => unsafe {
                curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "OPTIONS");
            },
            Method::PATCH => unsafe {
                curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "PATCH");
            },
        }

        let mut headers = List::new();
        for header in req.headers {
            let val_str = str::from_utf8(header.value);
            if val_str.is_err() {
                if CONFIG.get().unwrap().verbose {
                    eprintln!(
                        "Error: header value cannot be converted to string - {:x?}",
                        header.value
                    );
                }
                return None;
            }
            headers
                .append(&format!("{}: {}", header.name, val_str.unwrap()))
                .unwrap();
        }
        curl.http_headers(headers).unwrap();

        // Perform CURL request
        if let Err(err) = curl.perform() {
            if CONFIG.get().unwrap().verbose {
                println!("Error requesting URL: {}", req.path.unwrap());
                println!("err: {}", err);
            }
            // Failed, no resp
            return None;
        }
        *req_counter += 1;

        let duration = stopwatch.elapsed().as_secs_f32();

        let contents = curl.get_ref();
        let body = String::from_utf8_lossy(&contents.0);
        let headers = parse_headers(&contents.1);

        let resp = HttpResponse {
            body: body.to_string(),
            status_code: curl.response_code().unwrap(),
            duration,
            headers,
        };

        Some(resp)
    }

    pub fn do_request(
        &self,
        base_url: &str,
        curl: &mut Easy2<Collector>,
        ctx: &Context,
        req_counter: &mut u32,
        cache: &mut Cache,
    ) -> Option<HttpResponse> {
        if !self.raw.is_empty() {
            return self.raw_request(base_url, ctx, curl, req_counter);
        }

        let path = self.bake(ctx)?;
        if path.is_empty() || !path.contains(base_url) {
            return None;
        }

        // Skip caching below if we know the request is only happening once
        let key = CacheKey(self.method, self.path.clone());
        if !cache.can_cache(&key) {
            let res = self.internal_request(&path, curl, req_counter);
            if let Some(resp) = res {
                return Some(resp);
            } else {
                return None;
            }
        }

        if !cache.contains(&key) {
            let res = self.internal_request(&path, curl, req_counter);
            if let Some(resp) = res {
                cache.store(&key, Some(resp));
            } else {
                cache.store(&key, None);
            }
        }

        cache.get(&key)
    }
}
