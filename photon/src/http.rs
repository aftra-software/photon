use core::str;
use std::{
    collections::HashSet,
    sync::OnceLock,
    time::{Duration, Instant},
};

use bincode::{Decode, Encode};
use curl::easy::{Easy2, List};
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
    template::{Collector, Context, Method},
    template_executor::ExecutionOptions,
    PhotonContext,
};

pub static BRACKET_PATTERN: OnceLock<Regex> = OnceLock::new();

pub fn get_bracket_pattern() -> &'static Regex {
    BRACKET_PATTERN.get_or_init(|| {
        Regex::new("\\{\\{([^{}]*)}}").unwrap()
    })
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct HttpResponse {
    pub body: String,
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
}

fn bake_ctx(inp: &str, ctx: &Context, photon_ctx: &PhotonContext) -> Option<String> {
    let mut baked = inp.to_string();
    loop {
        let tmp = baked.clone();
        let matches: Vec<_> = get_bracket_pattern()
            .captures_iter(tmp.as_str())
            .collect();

        let mut updated = 0;
        for mat in matches.iter() {
            let compiled = compile_expression_validated(
                &mat.get(1).unwrap().as_str(),
                &photon_ctx.functions,
            );
            if let Ok(expr) = compiled {
                let res = expr.execute(&ctx, &photon_ctx.functions);
                if let Ok(Value::String(ret)) = res {
                    baked = baked.replace(mat.get(0).unwrap().as_str(), &ret);
                    updated += 1;
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
                    "Skipping request, {} missing parameters: [{}]",
                    unique.len(),
                    unique.into_iter().collect::<Vec<String>>().join(", ")
                );
                return None; // There's more to match that we couldn't match, invalid request
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

// Find CA certificate path, lazily instantiated static so consecutive calls are cached
fn find_ca() -> String {
    lazy_static::lazy_static! {
        static ref ca_path: String = {
            let r = openssl_probe::probe();
            r.cert_file
                    .expect("Unable to find certificate, cannot continue with HTTPS").to_string_lossy().into_owned()
        };
    }

    ca_path.clone()
}

fn curl_do_request(
    curl: &mut Easy2<Collector>,
    options: &ExecutionOptions,
    path: &str,
    body: &[u8],
    headers: &[String],
    method: Method,
) -> Option<HttpResponse> {
    // TODO: CURL Error Handling

    // Reset CURL context from last request
    curl.get_mut().reset(); // Reset collector
    curl.reset(); // Reset handle to initial state, keeping connections open

    // Manually find and set CA certificates, solves a lot of issues with statically linked libcurl.

    // TODO: I don't think any of the ca cert stuff is required since we just completely ignore any verification at this point
    // Remove?

    // TODO: Do additional validation to make sure we don't run into the case where
    // CURL can find the certs but openssl_probe can't.
    if path.starts_with("https") {
        // CURL resets CAINFO on Easy handle reset
        // https://github.com/curl/curl/blob/9e54db2707214ac1e4c332c606b692ec2e88cd43/lib/easy.c#L1082
        curl.cainfo(find_ca()).unwrap();
    }

    curl.cookie_list("ALL").unwrap(); // Reset stored cookies
    curl.useragent(&options.user_agent).unwrap();

    // Don't verify received cert
    curl.ssl_verify_peer(false).unwrap();
    curl.ssl_verify_host(false).unwrap();

    // Setup CURL context for this request
    curl.path_as_is(true).unwrap();
    //curl.follow_location(true).unwrap(); // Follow redirects, TODO: make configurable, AFAIK templates can change this opt
    curl.http_09_allowed(true).unwrap(); // Release builds run into http 0.9 not allowed errors, but dev builds not for some reason
    curl.accept_encoding("").unwrap(); // Tell CURL to accept compressed & automatically decompress body, some websites send compressed even when accept-encoding is not set.
    curl.timeout(Duration::from_secs(10)).unwrap(); // Max 10 seconds for entire request, TODO: Make configurable
    curl.url(path).unwrap();

    if !body.is_empty() {
        curl.post_fields_copy(body).unwrap();
    }

    match method {
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

    let mut parsed_headers = List::new();
    for header in headers.iter() {
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

    let contents = curl.get_ref();
    let body = String::from_utf8_lossy(&contents.0);
    let headers = parse_headers(&contents.1)?;
    debug!(
        "Got status {} for URL '{}', took {:.2}s",
        curl.response_code().unwrap(),
        path,
        duration
    );
    debug!("Body len: {}", body.len());

    let resp = HttpResponse {
        body: body.to_string(),
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
        curl: &mut Easy2<Collector>,
        req_counter: &mut u32,
    ) -> Option<HttpResponse> {
        let resp = curl_do_request(
            curl,
            options,
            path,
            self.body.as_bytes(),
            &self.headers,
            self.method,
        );
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
        curl: &mut Easy2<Collector>,
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
            verbose!(
                "Error parsing raw request: {} - request: '{}'",
                err,
                raw_data
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

        let resp = curl_do_request(
            curl,
            options,
            &path,
            body.as_bytes(),
            &self.headers,
            self.method,
        );
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
        curl: &mut Easy2<Collector>,
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
        let key = CacheKey(self.method, self.headers.clone(), self.path.clone());
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
