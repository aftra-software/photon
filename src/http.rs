use core::str;
use std::{sync::{Mutex, OnceLock}, thread::sleep, time::{Duration, Instant}
};

use curl::easy::{Easy2, List};
use curl_sys::CURLOPT_CUSTOMREQUEST;
use regex::Regex;

use crate::{
    cache::{Cache, CacheKey},
    dsl::{Value, GLOBAL_FUNCTIONS},
    parser::compile_expression,
    template::{Collector, Context, Method},
    CONFIG,
};

pub static BRACKET_PATTERN: OnceLock<Mutex<Regex>> = OnceLock::new();

// How long to sleep in our busy-loop between checks if we can read from a socket
const SLEEP_DURATION: Duration = Duration::from_nanos(1000); // 1/1000th of a millisecond

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
    pub raw: String,
}

fn bake_ctx(inp: &String, ctx: &Context) -> String {
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
            break;
        }
    }
    baked
}

impl HttpReq {
    /// Bakes the request with variables from `ctx`, returning the populated request path.
    pub fn bake(&self, ctx: &Context) -> String {
        bake_ctx(&self.path, ctx)
    }

    pub fn bake_raw(&self, ctx: &Context) -> String {
        bake_ctx(&self.raw, ctx)
    }

    fn internal_request(
        &self,
        path: &str,
        curl: &mut Easy2<Collector>,
        req_counter: &mut u32,
    ) -> Option<HttpResponse> {
        let pattern = BRACKET_PATTERN.get().unwrap().lock().unwrap();
        if pattern.is_match(path) {
            return None;
        }

        *req_counter += 1;
        let stopwatch = Instant::now();

        // TODO: CURL Error Handling

        // Reset CURL context from last request
        curl.get_mut().reset(); // Reset collector
        curl.reset(); // Reset handle to initial state, keeping connections open
        curl.cookie_list("ALL").unwrap(); // Reset stored cookies

        // Setup CURL context for this request
        curl.path_as_is(true).unwrap();
        curl.timeout(Duration::from_secs(10)).unwrap(); // Max 10 seconds for entire request, TODO: Make configurable
        curl.url(path).unwrap();

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
        let duration = stopwatch.elapsed().as_secs_f32();

        let contents = curl.get_ref();
        let body = String::from_utf8_lossy(&contents.0);

        let resp = HttpResponse {
            body: body.to_string(),
            status_code: curl.response_code().unwrap(),
            duration,
            headers: Vec::new(),
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
        // Reset CURL context from last request
        //curl.get_mut().reset(); // Reset collector
        curl.reset(); // Reset handle to initial state, keeping connections open
        curl.connect_only(true).unwrap();

        // Setup CURL context for this request
        //curl.path_as_is(true).unwrap(); // TODO: Not sure if needed
        //curl.timeout(Duration::from_secs(10)).unwrap(); // Max 10 seconds for entire request, TODO: Make configurable

        let mut raw_data = self.bake_raw(ctx);
        if let Value::String(hostname) = ctx.flatten_variables().get("Hostname").unwrap() {
            if !raw_data.contains(hostname) {
                // We don't want to do this request, expected hostname is missing
                return None;
            }
        }
        
        // 2x newline represent end of request in HTTP
        while !raw_data.ends_with("\n\n") {
            raw_data.push('\n');
        }

        println!("raw req: {raw_data}");

        if let Err(err) = curl.url(base_url) {
            if CONFIG.get().unwrap().verbose {
                eprintln!("CURL url error: {:?}", err);
            }
            return None;
        }
        if let Err(err) = curl.perform() {
            if CONFIG.get().unwrap().verbose {
                eprintln!("CURL connect error: {:?}", err);
            }
            return None;
        }

        let mut sent = 0;
        let target_sent = raw_data.as_bytes().len();
        loop {
            match curl.send(&raw_data.as_bytes()[sent..]) {
                Err(err) => {
                    if CONFIG.get().unwrap().verbose {
                        eprintln!("CURL send error: {:?}", err);
                    }
                    return None;
                }
                Ok(amnt) => {
                    sent += amnt;
                    if sent == target_sent {
                        break;
                    }
                }
            }
        }
        *req_counter += 1;
        
        let mut resp = Vec::new();
        loop {
            let mut resp_buf = [0u8; 4096]; // Receive 4KB at a time and push into `resp`
            let recvd = curl.recv(&mut resp_buf);
            match recvd {
                Ok(0) => {
                    break
                },
                Ok(len) => {
                    resp.extend_from_slice(&resp_buf[..len]);
                }
                Err(err) => {
                    if err.is_again() {
                        sleep(SLEEP_DURATION);
                    } else {
                        println!("DIFFERENT ERROR: {:?}", err);
                        break;
                    }
                }
            }
        }

        let body = String::from_utf8_lossy(&resp);

        println!("body: '{}'", body);

        None
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

        let path = self.bake(ctx);
        // TODO: maybe || now that raw is checked above
        if !path.is_empty() && !path.contains(base_url) {
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
