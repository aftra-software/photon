use core::str;
use std::{
    collections::HashSet,
    ffi::CStr,
    mem,
    sync::OnceLock,
    time::{Duration, Instant},
};

use bincode::{Decode, Encode};
use curl::easy::{Easy2, Handler, List, WriteError};
use curl_sys::CURLOPT_CUSTOMREQUEST;
use httparse::Status;
use photon_dsl::{
    dsl::{Value, VariableContainer},
    parser::compile_expression_validated,
};
use regex::Regex;

use crate::{
    cache::{Cache, CacheKey},
    get_config,
    template::{Context, Method},
    template_executor::ExecutionOptions,
    PhotonContext,
};

pub static BRACKET_PATTERN: OnceLock<Regex> = OnceLock::new();

pub fn get_bracket_pattern() -> &'static Regex {
    BRACKET_PATTERN.get_or_init(|| Regex::new(r"\{\{([^{}]*)}}").unwrap())
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub status_code: u32,
    pub duration: f32,
}

#[derive(Debug, Clone)]
pub struct HttpReq {
    pub method: Method,
    pub headers: Vec<String>,
    pub path: String,
    pub body: String,
    pub raw: String,
    pub follow_redirects: bool,
    pub max_redirects: Option<u32>,
}

pub(crate) fn bake_ctx(inp: &str, ctx: &Context, photon_ctx: &PhotonContext) -> Option<String> {
    let mut baked = inp.to_string();
    // TODO: Might be worth refactoring some of the code below.
    // Upper bound of 100 for bake_ctx, just to prevent any infinite-loops from self-creating expressions.
    for _ in 0..100 {
        let tmp = baked.clone();
        let matches: Vec<_> = get_bracket_pattern().captures_iter(tmp.as_str()).collect();

        let mut updated = 0;
        for mat in matches.iter() {
            let compiled =
                compile_expression_validated(mat.get(1).unwrap().as_str(), &photon_ctx.functions);
            if let Ok(expr) = compiled {
                let res = expr.execute(&ctx, &photon_ctx.functions);
                if let Ok(ret) = res {
                    // Replace one at a time to prevent things like {{rand_int(0, 100)}} giving always the same result in two places.
                    baked.replace_range(mat.get(0).unwrap().range(), &ret.to_string());
                    updated += 1;
                    break;
                }
            }
        }
        // End condition, when no more patterns match/can be replaced
        if updated == 0 {
            if !matches.is_empty() {
                let unique = matches
                    .iter()
                    .map(|m| m.get(1).unwrap().as_str().to_string())
                    .collect::<HashSet<String>>();
                verbose!(
                    "Skipping, {} missing parameters: [{}]",
                    unique.len(),
                    unique.into_iter().collect::<Vec<String>>().join(", ")
                );
                return None;
            }
            break;
        }
    }

    Some(baked)
}

fn parse_headers(contents: &[u8]) -> Option<Vec<(String, String)>> {
    String::from_utf8_lossy(contents)
        .split('\n')
        .filter(|chunk| !chunk.is_empty())
        .map(|a| {
            if let Some((key, value)) = a.split_once(':') {
                Some((key.to_string(), value.trim().to_string()))
            } else {
                // If this happens we're doing something very wrong
                verbose!(
                    "Error splitting header, shouldn't happen ever! If you see this report as bug!"
                );
                verbose!("Offending header: {a}");
                None
            }
        })
        .collect()
}
pub struct Collector(pub Vec<u8>, pub Vec<u8>);

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    fn header(&mut self, data: &[u8]) -> bool {
        // Make sure we're appending headers only, curl also gives us the HTTP response code header as well for some reason
        if data.contains(&b':') {
            self.1.extend_from_slice(data);
        }
        true
    }
}

impl Collector {
    pub fn reset(&mut self) {
        self.0.clear();
        self.1.clear();
    }
}

pub(crate) type CurlHandle = Easy2<Collector>;

fn curl_do_request(
    curl: &mut CurlHandle,
    options: &ExecutionOptions,
    req: &HttpReq,
    path: &str,
    body: &[u8],
) -> Option<HttpResponse> {
    // TODO: Proper CURL Error Handling

    // Reset CURL context from last request

    curl.get_mut().reset(); // Reset collector
    curl.reset(); // Reset handle to initial state, keeping connections open
    curl.cookie_list("ALL").unwrap(); // Reset stored cookies

    // Setup CURL context for this request

    curl.path_as_is(true).unwrap();
    curl.useragent(&options.user_agent).unwrap();
    // Don't verify any certs
    curl.ssl_verify_peer(false).unwrap();
    curl.ssl_verify_host(false).unwrap();
    // TODO: Handle host-redirects that only redirect on same host,
    // Curl doesn't natively support such behavior, so we might have to do some Location header shenanigans
    // Using the Collector. For now, both host-redirects and redirects behave the same
    curl.follow_location(req.follow_redirects).unwrap();
    // TODO: max_redirections param is incorrect, so for now we use an optional u32
    // see https://github.com/alexcrichton/curl-rust/issues/603
    if let Some(max_redirects) = req.max_redirects {
        curl.max_redirections(max_redirects).unwrap();
    }
    curl.http_09_allowed(true).unwrap(); // Release builds run into http 0.9 not allowed errors, but dev builds not for some reason
    curl.accept_encoding("").unwrap(); // Tell CURL to accept compressed & automatically decompress body, some websites send compressed even when accept-encoding is not set.
    curl.timeout(Duration::from_secs(10)).unwrap(); // Max 10 seconds for entire request, TODO: Make configurable
    curl.url(path).unwrap();

    if !body.is_empty() {
        curl.post_fields_copy(body).unwrap();
    }

    match req.method {
        Method::GET => {
            curl.get(true).unwrap();
        }
        Method::POST => {
            curl.post(true).unwrap();
        }
        // HTTP Methods outside of GET aren't implemented for CURL's Easy wrapper
        // So we interact with the raw curl handle manually, and set the request type to "custom"
        Method::DELETE => unsafe {
            curl_sys::curl_easy_setopt(
                curl.raw(),
                CURLOPT_CUSTOMREQUEST,
                CStr::from_bytes_with_nul(b"DELETE\0").unwrap(),
            );
        },
        Method::HEAD => unsafe {
            curl_sys::curl_easy_setopt(
                curl.raw(),
                CURLOPT_CUSTOMREQUEST,
                CStr::from_bytes_with_nul(b"HEAD\0").unwrap(),
            );
        },
        Method::OPTIONS => unsafe {
            curl_sys::curl_easy_setopt(
                curl.raw(),
                CURLOPT_CUSTOMREQUEST,
                CStr::from_bytes_with_nul(b"OPTIONS\0").unwrap(),
            );
        },
        Method::PATCH => unsafe {
            curl_sys::curl_easy_setopt(
                curl.raw(),
                CURLOPT_CUSTOMREQUEST,
                CStr::from_bytes_with_nul(b"PATCH\0").unwrap(),
            );
        },
    }

    let mut parsed_headers = List::new();
    for header in &req.headers {
        parsed_headers.append(header).unwrap();
    }
    for header in &options.extra_headers {
        parsed_headers.append(header).unwrap();
    }
    curl.http_headers(parsed_headers).unwrap();

    let stopwatch = Instant::now();
    // Perform CURL request
    if let Err(err) = curl.perform() {
        verbose!("Error requesting URL: '{}'", path);
        verbose!("err: {}", err);
        // Failed, no resp
        return None;
    }

    let duration = stopwatch.elapsed().as_secs_f32();

    debug!(
        "Got status {} for URL '{}', took {:.2}s",
        curl.response_code().unwrap(),
        path,
        duration
    );

    let contents = curl.get_mut();
    let headers = parse_headers(&contents.1)?;
    debug!("Body len: {}", contents.0.len());

    let resp = HttpResponse {
        body: mem::take(&mut contents.0),
        status_code: curl.response_code().unwrap(),
        duration,
        headers,
    };

    Some(resp)
}

impl HttpReq {
    /// Bakes the request with variables from `ctx`, returning the populated request path.
    pub fn bake(&self, ctx: &Context, photon_ctx: &PhotonContext) -> Option<String> {
        bake_ctx(&self.path, ctx, photon_ctx)
    }

    pub fn bake_raw(&self, ctx: &Context, photon_ctx: &PhotonContext) -> Option<String> {
        bake_ctx(&self.raw, ctx, photon_ctx)
    }

    fn internal_request(
        &self,
        path: &str,
        options: &ExecutionOptions,
        curl: &mut CurlHandle,
        req_counter: &mut u32,
    ) -> Option<HttpResponse> {
        let resp = curl_do_request(curl, options, self, path, self.body.as_bytes());
        if resp.is_some() {
            // Successful request
            *req_counter += 1;
        }
        resp
    }

    fn raw_request(
        &self,
        base_url: &str,
        ctx: &Context,
        photon_ctx: &PhotonContext,
        options: &ExecutionOptions,
        curl: &mut CurlHandle,
        req_counter: &mut u32,
    ) -> Option<HttpResponse> {
        let mut raw_data = self.bake_raw(ctx, photon_ctx)?;
        if let Value::String(hostname) = ctx.get("Hostname").unwrap() {
            if !raw_data.contains(&hostname) {
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
            debug!(
                "Error parsing raw request: {} - request: '{}'",
                err, raw_data
            );
            return None;
        }

        let len = match parsed.unwrap() {
            Status::Complete(len) => len,
            Status::Partial => raw_data.len(), // Shouldn't happen, but if it does, we should still have parsed the entire request
        };

        let body = &raw_data[len..];

        if req.path.is_none() {
            verbose!("Error: Raw request parsed 'path' missing");
            return None;
        }

        let raw_path = if !req.path.unwrap().starts_with("http") {
            format!("{}{}", base_url, req.path.unwrap())
        } else {
            // Handle absolute-form requests https://httpwg.org/specs/rfc9112.html#absolute-form
            req.path.unwrap().to_string()
        };

        // Some templates accidentally add an extra space to the url somehow
        let path = raw_path.trim().to_string();

        let mut headers = Vec::new();
        for header in req.headers {
            let val_str = str::from_utf8(header.value);
            if val_str.is_err() {
                verbose!(
                    "Error: header value cannot be converted to string - {:x?}",
                    header.value
                );
                return None;
            }
            headers.push(format!("{}: {}", header.name, val_str.unwrap()));
        }

        let resp = curl_do_request(curl, options, self, &path, body.as_bytes());
        if resp.is_some() {
            // Successful request
            *req_counter += 1;
        }
        resp
    }

    pub fn do_request(
        &self,
        base_url: &str,
        options: &ExecutionOptions,
        curl: &mut CurlHandle,
        ctx: &Context,
        photon_ctx: &PhotonContext,
        req_counter: &mut u32,
        cache: &mut Cache,
    ) -> Option<HttpResponse> {
        if !self.raw.is_empty() {
            return self.raw_request(base_url, ctx, photon_ctx, options, curl, req_counter);
        }

        let path = self.bake(ctx, photon_ctx)?;
        if path.is_empty() || !path.contains(base_url) {
            return None;
        }

        // Some templates accidentally add an extra space to the url somehow
        let path = path.trim().to_string();

        // Skip caching below if we know the request is only happening once
        // XXX: Currently caches all requests, regardless of if their responses are re-used
        let key = CacheKey(self.method, self.headers.clone(), path.clone());
        if !cache.can_cache(&key) {
            let res = self.internal_request(&path, options, curl, req_counter);
            if let Some(resp) = res {
                return Some(resp);
            } else {
                return None;
            }
        }

        if !cache.contains(&key) {
            let res = self.internal_request(&path, options, curl, req_counter);
            if let Some(resp) = res {
                cache.store(&key, Some(resp));
            } else {
                cache.store(&key, None);
            }
        }

        cache.get(&key)
    }
}
