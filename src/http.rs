use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use regex::Regex;
use ureq::{Agent, Response};

use crate::template::Method;

pub static IGNORE_PATTERN: OnceLock<Mutex<Regex>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub status_code: u8,
}

#[derive(Debug)]
pub struct HttpReq {
    pub method: Method,
    pub path: String,
    pub raw: String,
}

fn parse_response(inp: Response) -> HttpResponse {
    let headers: Vec<(String, String)> = inp
        .headers_names()
        .iter()
        .map(|name| (name.clone(), inp.header(name).unwrap().to_string()))
        .collect();
    HttpResponse {
        headers,
        status_code: inp.status() as u8,
        body: inp.into_string().unwrap(),
    }
}

impl HttpReq {
    pub fn bake(&self, base_url: &str) -> String {
        self.path.replace("{{BaseURL}}", base_url)
    }
    pub fn bake_raw(&self, base_url: &str) -> String {
        self.raw
            .replace("{{BaseURL}}", base_url)
            .replace("HTTP/2", "HTTP/1.1")
    }

    fn internal_request(&self, path: &str, agent: &Agent) -> Option<Response> {
        let pattern = IGNORE_PATTERN.get().unwrap().lock().unwrap();
        if pattern.is_match(&path) {
            return None;
        }

        let res = agent.get(&path).call();
        match res {
            Err(err) => match err {
                ureq::Error::Status(_, resp) => Some(resp),
                _ => {
                    println!("Err: {}", err);
                    println!("    - {}", path);
                    None
                }
            },
            Ok(resp) => Some(resp),
        }
    }

    fn raw_request(&self, base_url: &str, agent: &Agent) -> Option<HttpResponse> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let baked_raw = self.bake_raw(base_url);
        let res = req.parse(baked_raw.as_bytes());

        let pattern = IGNORE_PATTERN.get().unwrap().lock().unwrap();
        if pattern.is_match(&baked_raw) {
            return None;
        }

        match res {
            Ok(_) => {
                if req.method.is_some() && req.path.is_some() {
                    let resp = agent.request(req.method.unwrap(), req.path.unwrap()).call();
                    match resp {
                        Err(err) => match err {
                            ureq::Error::Status(_, resp) => Some(parse_response(resp)),
                            _ => {
                                println!("Err: {}", err);
                                println!("    - {}", req.path.unwrap());
                                None
                            }
                        },
                        Ok(resp) => Some(parse_response(resp)),
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
        req_counter: &mut u32,
        cache: &mut HashMap<(Method, String), Option<HttpResponse>>,
        allowed_cache: &HashMap<(Method, String), u16>
    ) -> Option<HttpResponse> {
        let path = self.bake(base_url);
        if !path.is_empty() && !path.contains(base_url) {
            return None;
        }

        if !self.raw.is_empty() {
            *req_counter += 1;
            return self.raw_request(base_url, agent);
        }
        
        // Skip caching below if we know the request is only happening once
        if !allowed_cache.contains_key(&(self.method, self.path.clone())) {
            *req_counter += 1;
            let res = self.internal_request(&path, agent);
            if let Some(resp) = res {
                return Some(parse_response(resp));
            } else {
                return None;
            }
        }

        let key = (self.method, path.clone());
        
        if cache.contains_key(&key) {
            return cache.get(&(self.method, path)).unwrap().clone();
        }
        *req_counter += 1;
        let res = self.internal_request(&path, agent);
        if let Some(resp) = res {
            cache.insert(key.clone(), Some(parse_response(resp)));
        } else {
            cache.insert(key.clone(), None);
        }

        return cache.get(&key).unwrap().clone();
    }
}
