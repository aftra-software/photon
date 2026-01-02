use photon_dsl::dsl::{CompiledExpression, Value};

use crate::{
    PhotonContext,
    cache::RegexCache,
    get_config,
    http::{HttpResponse, bake_ctx, get_bracket_pattern},
    template::{Condition, Context},
};

#[derive(Debug, Clone)]
pub enum MatcherType {
    Word(Vec<String>),
    Binary(Vec<String>),
    DSL(Vec<CompiledExpression>),
    Regex(Vec<u32>), // indicies into RegexCache
    Status(Vec<u32>),
}

#[derive(Debug, Clone)]
pub enum ExtractorType {
    Matcher(MatcherType),
    Kval(Vec<String>),
}

#[derive(Debug, Clone, Copy)]
pub enum ExtractorPart {
    HeaderCookie, // Either Header or Cookie, with Header having priority
    Header,
    Cookie,
    // Response Parts
    Body,
    Raw,
    All,
    Response, // Seems to be an alias for All, https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md#httprequest
}

#[derive(Debug, Clone, Copy)]
pub enum ResponsePart {
    Body,
    Raw,
    Header,
    All,
    Response, // Seems to be an alias for All, https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md#httprequest
}

#[derive(Debug, Clone)]
pub struct Matcher {
    pub r#type: MatcherType,
    pub name: Option<String>,
    pub negative: bool,
    pub group: Option<i64>, // Regex group number, None represents entire regex match
    pub internal: bool,     // Used for workflows, matches, but does not print
    pub part: ResponsePart,
    pub condition: Condition,
}

#[derive(Debug, Clone)]
pub struct Extractor {
    pub r#type: ExtractorType,
    pub name: Option<String>,
    pub group: Option<i64>, // Regex group number, None represents entire regex match
    pub internal: bool,     // Used for workflows, matches, but does not print
    pub part: ExtractorPart,
}

fn extractor_part_to_string(data: &HttpResponse, part: ExtractorPart) -> String {
    match part {
        // Map 1:1 Extractor -> Response parts
        ExtractorPart::All => response_to_string(data, ResponsePart::All),
        ExtractorPart::Response => response_to_string(data, ResponsePart::Response),
        ExtractorPart::Body => response_to_string(data, ResponsePart::Body),
        ExtractorPart::Raw => response_to_string(data, ResponsePart::Raw),
        // Cookies are in Headers, so HeaderCookie maps to Headers string
        ExtractorPart::Header | ExtractorPart::HeaderCookie => {
            response_to_string(data, ResponsePart::Header)
        }

        // Concatenated all cookie headers into a single string
        ExtractorPart::Cookie => data
            .headers
            .iter()
            .filter(|(key, _)| key.to_lowercase() == "set-cookie")
            .map(|(_, value)| format!("{value}\n"))
            .collect::<Vec<String>>()
            .concat(),
    }
}

// Get (Key, Value) pairs from cookies
fn extractor_get_cookies(data: &HttpResponse) -> Vec<(String, String)> {
    data.headers
        .iter()
        .filter(|(key, _)| key.to_lowercase() == "set-cookie")
        .filter_map(|(_, value)| {
            let cookie_kv = value.split(';').next().unwrap().split_once('=');
            if let Some((key, value)) = cookie_kv {
                // https://docs.projectdiscovery.io/templates/reference/extractors#kval-extractor
                // Nuclei kval extractors don't support dashes, so we modify the key to conform to their spec
                Some((String::from(key).replace('-', "_"), String::from(value)))
            } else {
                None
            }
        })
        .collect::<Vec<(String, String)>>()
}

fn response_to_string(data: &HttpResponse, part: ResponsePart) -> String {
    match part {
        ResponsePart::All | ResponsePart::Response => {
            // TODO: Actually return proper All, now easier using CURL
            let mut parts = vec![];
            data.headers
                .iter()
                .for_each(|(k, v)| parts.push(format!("{k}: {v}\n")));
            parts.push(String::from_utf8_lossy(&data.body).into());
            parts.concat()
        }
        ResponsePart::Body => String::from_utf8_lossy(&data.body).into(),
        ResponsePart::Header => data
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}\n"))
            .collect::<Vec<String>>()
            .concat(),
        ResponsePart::Raw => {
            // TODO: Actually return Raw
            let mut parts = vec![];
            data.headers
                .iter()
                .for_each(|(k, v)| parts.push(format!("{k}: {v}\n")));
            parts.push(String::from_utf8_lossy(&data.body).into());
            parts.concat()
        }
    }
}

fn contains_with_dsl(
    haystack: &str,
    needle: &str,
    ctx: &Context,
    photon_ctx: &PhotonContext,
) -> bool {
    if needle.contains("{{") && get_bracket_pattern().is_match(needle) {
        if let Some(baked) = bake_ctx(needle, ctx, photon_ctx) {
            haystack.contains(&baked)
        } else {
            false
        }
    } else {
        haystack.contains(needle)
    }
}

impl Matcher {
    pub fn matches(
        &self,
        data: &HttpResponse,
        regex_cache: &RegexCache,
        context: &Context,
        photon_ctx: &PhotonContext,
    ) -> bool {
        if matches!(self.r#type, MatcherType::Status(_)) {
            return self.matches_status(data.status_code);
        }

        let data = response_to_string(data, self.part);
        match &self.r#type {
            MatcherType::DSL(dsls) => {
                if self.condition == Condition::OR {
                    dsls.iter().any(|expr| {
                        let res = expr.execute(&context, &photon_ctx.functions);
                        matches!(res, Ok(Value::Boolean(true)))
                    })
                } else {
                    dsls.iter().all(|expr| {
                        let res = expr.execute(&context, &photon_ctx.functions);
                        matches!(res, Ok(Value::Boolean(true)))
                    })
                }
            }
            MatcherType::Regex(regexes) => {
                if self.condition == Condition::OR {
                    regexes
                        .iter()
                        .any(|pattern| regex_cache.matches(*pattern, &data))
                } else {
                    regexes
                        .iter()
                        .all(|pattern| regex_cache.matches(*pattern, &data))
                }
            }
            MatcherType::Word(words) => {
                if self.condition == Condition::OR {
                    words
                        .iter()
                        .any(|needle| contains_with_dsl(&data, needle, context, photon_ctx))
                } else {
                    words
                        .iter()
                        .all(|needle| contains_with_dsl(&data, needle, context, photon_ctx))
                }
            }
            MatcherType::Binary(hexs) => {
                if self.condition == Condition::OR {
                    hexs.iter()
                        .any(|needle| contains_with_dsl(&data, needle, context, photon_ctx))
                } else {
                    hexs.iter()
                        .all(|needle| contains_with_dsl(&data, needle, context, photon_ctx))
                }
            }
            MatcherType::Status(_) => false,
        }
    }

    fn matches_status(&self, status: u32) -> bool {
        match &self.r#type {
            MatcherType::Status(statuses) => statuses.contains(&status),
            _ => unreachable!("Cannot match status when type != MatcherType::Status"),
        }
    }
}

impl Extractor {
    // TODO: Allow multiple returns, with matchers being ran with all permutations
    // of all possible extracted values? That's the logic according to testing with Nuclei
    // where the matcher is ran like this pseudo logic:
    // values.iter().any(|val| {
    //    context.set(name, val)
    //    matcher.matches(context)
    //})
    // if either matches, both values are added into the match
    pub fn extract(
        &self,
        data: &HttpResponse,
        regex_cache: &RegexCache,
        context: &Context,
        photon_ctx: &PhotonContext,
    ) -> Option<Value> {
        match &self.r#type {
            ExtractorType::Matcher(matcher) => {
                if let MatcherType::Status(_) = matcher {
                    return self.matches_status(data.status_code);
                }

                let data = extractor_part_to_string(data, self.part);
                match &matcher {
                    MatcherType::DSL(dsls) => dsls
                        .iter()
                        .filter_map(|expr| expr.execute(&context, &photon_ctx.functions).ok())
                        .next(),
                    MatcherType::Regex(regexes) => regexes
                        .iter()
                        .filter_map(|pattern| {
                            regex_cache.match_group(
                                *pattern,
                                &data,
                                self.group.unwrap_or(0) as usize,
                            )
                        })
                        .next()
                        .map(Value::String),
                    MatcherType::Word(_) => {
                        debug!("Extractor does not support Word matching");
                        None
                    }
                    MatcherType::Binary(_) => {
                        debug!("Extractor does not support Binary matching");
                        None
                    }
                    MatcherType::Status(_) => None,
                }
            }
            ExtractorType::Kval(fields) => {
                let cookies = extractor_get_cookies(data);
                match self.part {
                    ExtractorPart::Cookie | ExtractorPart::Header => {
                        let kv = match self.part {
                            ExtractorPart::Cookie => &cookies,
                            ExtractorPart::Header => &data.headers,
                            _ => unreachable!(),
                        };
                        for field in fields {
                            if let Some((_, value)) = kv
                                .iter()
                                .find(|(k, _)| k.to_lowercase() == field.to_lowercase())
                            {
                                return Some(Value::String(value.clone()));
                            }
                        }
                    }
                    ExtractorPart::HeaderCookie => {
                        for field in fields {
                            for kv in [&data.headers, &cookies] {
                                if let Some((_, value)) = kv
                                    .iter()
                                    .find(|(k, _)| k.to_lowercase() == field.to_lowercase())
                                {
                                    return Some(Value::String(value.clone()));
                                }
                            }
                        }
                    }
                    _ => return None,
                }
                None
            }
        }
    }

    fn matches_status(&self, status: u32) -> Option<Value> {
        match &self.r#type {
            // TODO: Maybe this should be different/Not implemented for Extractor
            ExtractorType::Matcher(MatcherType::Status(_)) => Some(Value::Int(status as i64)),
            _ => unreachable!("Cannot match status when type != MatcherType::Status"),
        }
    }
}
