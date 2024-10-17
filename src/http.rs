use std::{
    sync::{Mutex, OnceLock},
    time::Instant,
};

use regex::Regex;
use ureq::{Agent, Response};

use crate::{
    cache::{Cache, CacheKey},
    dsl::{Value, GLOBAL_FUNCTIONS},
    parser::compile_expression,
    template::{Context, Method},
    CONFIG,
};

pub static BRACKET_PATTERN: OnceLock<Mutex<Regex>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub status_code: u8,
    pub duration: f32,
}

#[derive(Debug)]
pub struct HttpReq {
    pub method: Method,
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
        status_code: inp.status() as u8,
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
        agent: &Agent,
        req_counter: &mut u32,
    ) -> Option<(Response, f32)> {
        let pattern = BRACKET_PATTERN.get().unwrap().lock().unwrap();
        if pattern.is_match(path) {
            return None;
        }

        *req_counter += 1;
        let stopwatch = Instant::now();
        let res = agent.get(path).call();
        let duration = stopwatch.elapsed().as_secs_f32();
        match res {
            Err(err) => match err {
                ureq::Error::Status(_, resp) => Some((resp, duration)),
                _ => {
                    if CONFIG.get().unwrap().verbose {
                        println!("Err: {}", err);
                        println!("    - {}", path);
                    }
                    None
                }
            },
            Ok(resp) => Some((resp, duration)),
        }
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
            let res = self.internal_request(&path, agent, req_counter);
            if let Some(resp) = res {
                return Some(parse_response(resp.0, resp.1));
            } else {
                return None;
            }
        }

        if !cache.contains(&key) {
            let res = self.internal_request(&path, agent, req_counter);
            if let Some(resp) = res {
                cache.store(&key, Some(parse_response(resp.0, resp.1)));
            } else {
                cache.store(&key, None);
            }
        }

        cache.get(&key)
    }
}
