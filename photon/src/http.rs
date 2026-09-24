use core::str;
use std::{
    mem,
    time::{Duration, Instant},
};

use crate::{
    PhotonContext,
    cache::CacheKey,
    get_config,
    template::{Context, Method},
    template_executor::{ExecutionContext, ExecutionOptions},
    template_string::{TemplateHeader, TemplateString},
};
use bincode::{Decode, Encode};
use curl::easy::{Easy2, Handler, List, WriteError};
use curl_sys::CURLOPT_CUSTOMREQUEST;
use httparse::Status;
use photon_dsl::dsl::{Value, VariableContainer};

#[derive(Debug, Clone, Encode, Decode)]
pub struct HttpResponse {
    pub req_url: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub status_code: u32,
    pub duration: f32,
}

#[derive(Debug, Clone)]
pub struct HttpReq {
    pub method: Method,
    pub headers: Vec<TemplateHeader>,
    pub path: TemplateString,
    pub body: TemplateString,
    pub raw: Option<TemplateString>,
    pub follow_redirects: bool,
    pub max_redirects: Option<u32>,
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
    method: Method,
    headers: &[String],
    follow_redirects: bool,
    max_redirects: Option<u32>,
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
    curl.follow_location(follow_redirects).unwrap();
    // TODO: max_redirections param is incorrect, so for now we use an optional u32
    // see https://github.com/alexcrichton/curl-rust/issues/603
    if let Some(max_redirects) = max_redirects {
        curl.max_redirections(max_redirects).unwrap();
    }
    curl.http_09_allowed(true).unwrap(); // Release builds run into http 0.9 not allowed errors, but dev builds not for some reason
    curl.accept_encoding("").unwrap(); // Tell CURL to accept compressed & automatically decompress body, some websites send compressed even when accept-encoding is not set.
    curl.timeout(Duration::from_secs(10)).unwrap(); // Max 10 seconds for entire request, TODO: Make configurable
    curl.url(path).unwrap();

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
            curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, c"DELETE");
        },
        Method::HEAD => unsafe {
            curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, c"HEAD");
        },
        Method::OPTIONS => unsafe {
            curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, c"OPTIONS");
        },
        Method::PATCH => unsafe {
            curl_sys::curl_easy_setopt(curl.raw(), CURLOPT_CUSTOMREQUEST, c"PATCH");
        },
    }

    let mut parsed_headers = List::new();
    for header in headers {
        parsed_headers.append(header).unwrap();
    }
    for header in &options.extra_headers {
        parsed_headers.append(header).unwrap();
    }
    curl.http_headers(parsed_headers).unwrap();

    if !body.is_empty() {
        curl.post_fields_copy(body).unwrap();
    }

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
        req_url: String::from(path),
        body: mem::take(&mut contents.0),
        status_code: curl.response_code().unwrap(),
        duration,
        headers,
    };

    Some(resp)
}

impl HttpReq {
    fn internal_request(
        &self,
        path: &str,
        headers: &[String],
        body: &[u8],
        options: &ExecutionOptions,
        curl: &mut CurlHandle,
        req_counter: &mut u32,
    ) -> Option<HttpResponse> {
        let resp = curl_do_request(
            curl,
            options,
            self.method,
            headers,
            self.follow_redirects,
            self.max_redirects,
            path,
            body,
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
        exec_ctx: &mut ExecutionContext,
        photon_ctx: &PhotonContext,
        curl: &mut CurlHandle,
    ) -> Option<HttpResponse> {
        let mut raw_data = self.raw.as_ref()?.bake(ctx, photon_ctx).ok()?;
        if let Value::String(hostname) = ctx.get("Hostname")? {
            if !raw_data.contains(&hostname) {
                // We don't want to do this request, expected hostname is missing
                return None;
            }
        }

        // We want carriage return instead of only newlines
        raw_data = raw_data.replace("\n", "\r\n");

        // Makes parsing that much more reliable, since HTTP requests end with two newlines
        while !raw_data.ends_with("\n\n") {
            raw_data.push('\n');
        }

        // TODO: Handle timeout thing properly, for now we strip it away to be able to parse the request
        if raw_data.starts_with("@timeout") {
            raw_data = raw_data.split_once("\n").unwrap().1.to_string();
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

        // Build a dummy request from the parsed raw request
        let method = match req.method {
            None => Method::GET,
            Some("GET") => Method::GET,
            Some("POST") => Method::POST,
            Some("DELETE") => Method::DELETE,
            Some("HEAD") => Method::HEAD,
            Some("PATCH") => Method::PATCH,
            Some("OPTIONS") => Method::OPTIONS,
            Some(_) => Method::GET,
        };

        let resp = curl_do_request(
            curl,
            &exec_ctx.options,
            method,
            &headers,
            self.follow_redirects,
            self.max_redirects,
            &path,
            body.as_bytes(),
        );
        if resp.is_some() {
            // Successful request
            exec_ctx.total_reqs += 1;
        }
        resp
    }

    pub fn do_request(
        &self,
        base_url: &str,
        exec_ctx: &mut ExecutionContext,
        photon_ctx: &PhotonContext,
        curl: &mut CurlHandle,
        ctx: &Context,
    ) -> Option<HttpResponse> {
        if self.raw.is_some() {
            return self.raw_request(base_url, ctx, exec_ctx, photon_ctx, curl);
        }

        let path = self.path.bake(ctx, photon_ctx).ok()?;
        if path.is_empty() || !path.contains(base_url) {
            return None;
        }

        // Some templates accidentally add an extra space to the url somehow
        let path = path.trim().to_string();
        let body = self.body.bake(ctx, photon_ctx).ok()?;
        let headers = self
            .headers
            .iter()
            .map(|header| header.bake(ctx, photon_ctx))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;

        // Skip caching below if we know the request is only happening once
        // XXX: Currently caches all requests, regardless of if their responses are re-used
        let key = CacheKey {
            method: self.method,
            headers: headers.clone(),
            path: path.clone(),
            body: body.as_bytes().to_vec(),
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            extra_headers: exec_ctx.options.extra_headers.clone(),
            user_agent: exec_ctx.options.user_agent.clone(),
        };
        if !exec_ctx.cache.can_cache(&key) {
            let res = self.internal_request(
                &path,
                &headers,
                body.as_bytes(),
                &exec_ctx.options,
                curl,
                &mut exec_ctx.total_reqs,
            );
            if let Some(resp) = res {
                return Some(resp);
            } else {
                return None;
            }
        }

        if !exec_ctx.cache.contains(&key) {
            let res = self.internal_request(
                &path,
                &headers,
                body.as_bytes(),
                &exec_ctx.options,
                curl,
                &mut exec_ctx.total_reqs,
            );
            if let Some(resp) = res {
                exec_ctx.cache.store(&key, Some(resp));
            } else {
                exec_ctx.cache.store(&key, None);
            }
        }

        exec_ctx.cache.get(&key)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use curl::easy::Easy2;
    use rustc_hash::FxHashMap;

    use super::{Collector, HttpReq};
    use crate::{
        PhotonContext,
        cache::{Cache, RegexCache},
        init_functions,
        template::{Context, ContextScope, Method},
        template_executor::{ExecutionContext, ExecutionOptions},
        template_string::{TemplateHeader, TemplateString},
    };

    #[test]
    fn structured_request_bakes_before_sending_and_caching() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut data = Vec::new();
                let mut buffer = [0; 1024];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    data.extend_from_slice(&buffer[..read]);
                    let headers_end = data
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|position| position + 4);
                    let Some(headers_end) = headers_end else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&data[..headers_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if data.len() >= headers_end + content_length {
                        break;
                    }
                }
                requests.push(String::from_utf8(data).unwrap());
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
            }
            requests
        });

        let base_url = format!("http://{address}");
        let request = HttpReq {
            method: Method::POST,
            headers: vec![TemplateHeader::new("X-Token", "{{token}}")],
            path: TemplateString::from(format!("{base_url}/login")),
            body: TemplateString::from("username={{username}}"),
            raw: None,
            follow_redirects: false,
            max_redirects: None,
        };
        let mut exec_ctx = ExecutionContext {
            options: ExecutionOptions::default(),
            ctx: Context::new_scoped_with_parent(ContextScope::Global, None),
            total_reqs: 0,
            cache: Cache::new(Default::default()),
            regex_cache: RegexCache::new(),
        };
        let photon_ctx = PhotonContext {
            functions: init_functions(),
        };
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));

        for (username, token) in [("admin", "first"), ("root", "second"), ("admin", "first")] {
            let mut ctx = Context {
                variables: FxHashMap::default(),
                parent: None,
                scope: ContextScope::Request,
            };
            ctx.insert_str("username", username);
            ctx.insert_str("token", token);
            assert!(
                request
                    .do_request(&base_url, &mut exec_ctx, &photon_ctx, &mut curl, &ctx)
                    .is_some()
            );
        }

        let requests = server.join().unwrap();
        assert_eq!(exec_ctx.total_reqs, 2);
        assert!(requests[0].contains("X-Token: first"));
        assert!(requests[0].ends_with("username=admin"));
        assert!(requests[1].contains("X-Token: second"));
        assert!(requests[1].ends_with("username=root"));
    }
}
