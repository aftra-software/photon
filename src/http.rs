use core::str;
use std::{
    sync::{Mutex, OnceLock}, time::Instant
};

use curl::easy::{Easy2, List};
use curl_sys::CURLOPT_CUSTOMREQUEST;
use regex::Regex;
use ureq::{Agent, Response};

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
    pub raw: String,
}

fn parse_response(inp: Response, duration: f32) -> HttpResponse {
    let headers: Vec<(String, String)> = inp
        .headers_names()
        .iter()
        .map(|name| (name.clone(), inp.header(name).unwrap().to_string()))
        .collect();
    HttpResponse {
        headers,
        status_code: inp.status() as u32,
        body: inp.into_string().unwrap(),
        duration,
    }
}

impl HttpReq {
    /// Bakes the request with variables from `ctx`, returning the populated request path.
    pub fn bake(&self, ctx: &Context) -> String {
        let mut path = self.path.clone();
        // TODO: Do this repeatedly, continue matching and replacing until nothing can be replaced again
        // Pattern always matches inner-most brackets, so we need to do it multiple times
        for mat in BRACKET_PATTERN
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .find_iter(&self.path)
        {
            let flattened = ctx.flatten_variables();
            let compiled = compile_expression(&mat.as_str()[2..mat.len() - 2]);
            if let Ok(expr) = compiled {
                let res = expr.execute(&flattened, GLOBAL_FUNCTIONS.get().unwrap());
                if let Ok(Value::String(ret)) = res {
                    path = path.replace(mat.as_str(), &ret);
                }
            }
        }
        path
    }

    pub fn bake_raw(&self, base_url: &str) -> String {
        self.raw
            .replace("{{BaseURL}}", base_url)
            .replace("HTTP/2", "HTTP/1.1")
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
        curl.url(path).unwrap();

        match self.method {
            Method::GET => {
                curl.get(true).unwrap();
            },
            Method::POST => {
                curl.post(true).unwrap();
            },
            // HTTP Methods outside of GET aren't implemented for CURL's Easy wrapper
            // So we interact with the raw curl handle manually, and set the request type to "custom"
            Method::DELETE => {
                unsafe {
                    curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "DELETE");
                }
            },
            Method::HEAD => {
                unsafe {
                    curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "HEAD");
                }
            },
            Method::OPTIONS => {
                unsafe {
                    curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "OPTIONS");
                }
            },
            Method::PATCH => {
                unsafe {
                    curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, "PATCH");
                }
            }
        }

        let mut headers = List::new();
        for header in self.headers.iter() {
            headers.append(&header).unwrap();
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
            duration: duration, // Filled in later
            headers: Vec::new()
        };

        Some(resp)
    }

    fn raw_request(
        &self,
        base_url: &str,
        agent: &Agent,
        req_counter: &mut u32,
    ) -> Option<HttpResponse> {
        return None;
        // TODO: implement and handle better, needs more string replacements to work and such
        // e.g. {{Hostname}}
        // Also need to send the actual raw request
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let baked_raw = self.bake_raw(base_url);

        if !baked_raw.is_empty() && !baked_raw.contains(base_url) {
            return None;
        }

        let res = req.parse(baked_raw.as_bytes());

        let pattern = BRACKET_PATTERN.get().unwrap().lock().unwrap();
        if pattern.is_match(&baked_raw) {
            return None;
        }

        match res {
            Ok(_) => {
                if req.method.is_some() && req.path.is_some() {
                    *req_counter += 1;
                    let stopwatch = Instant::now();
                    let resp = agent.request(req.method.unwrap(), req.path.unwrap()).call();
                    let duration = stopwatch.elapsed().as_secs_f32();
                    match resp {
                        Err(err) => match err {
                            ureq::Error::Status(_, resp) => Some(parse_response(resp, duration)),
                            _ => {
                                if CONFIG.get().unwrap().verbose {
                                    println!("Err: {}", err);
                                    println!("    - {}", req.path.unwrap());
                                }
                                None
                            }
                        },
                        Ok(resp) => Some(parse_response(resp, duration)),
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub fn do_request(
        &self,
        base_url: &str,
        agent: &Agent,
        curl: &mut Easy2<Collector>,
        ctx: &Context,
        req_counter: &mut u32,
        cache: &mut Cache,
    ) -> Option<HttpResponse> {
        let path = self.bake(ctx);
        if !path.is_empty() && !path.contains(base_url) {
            return None;
        }

        if !self.raw.is_empty() {
            return self.raw_request(base_url, agent, req_counter);
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
