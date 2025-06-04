use std::{collections::HashMap, fmt::Debug, fs};

use photon_dsl::{
    dsl::{CompiledExpression, Value},
    parser::compile_expression,
};
use walkdir::WalkDir;
use yaml_rust2::{Yaml, YamlLoader};

use crate::{
    cache::{Cache, CacheKey, RegexCache},
    get_config,
    http::{get_bracket_pattern, HttpReq},
    template::{
        Condition, Extractor, HttpRequest, Info, Matcher, MatcherType, Method, ResponsePart,
        Severity, Template,
    },
};

#[derive(Debug)]
#[allow(dead_code)] // We never explicitly read from the inner fields, only debug log
pub enum TemplateError {
    MissingField(String),
    InvalidValue(String),
    InvalidDSL(String),
    CantReadFile,
    InvalidYaml,
    Todo(String),
}

fn load_yaml_from_file(file: &str) -> Result<Vec<Yaml>, TemplateError> {
    let file_contents = match fs::read_to_string(file) {
        Ok(contents) => contents,
        Err(_) => return Err(TemplateError::CantReadFile),
    };

    let parsed = match YamlLoader::load_from_str(&file_contents) {
        Ok(content) => content,
        Err(_) => return Err(TemplateError::InvalidYaml),
    };

    if parsed.len() != 1 {
        return Err(TemplateError::InvalidYaml);
    }

    Ok(parsed)
}

fn map_severity(severity: &str) -> Option<Severity> {
    match severity.to_lowercase().as_str() {
        "unknown" => Some(Severity::Unknown),
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn map_method(method: &str) -> Option<Method> {
    match method.to_lowercase().as_str() {
        "get" => Some(Method::GET),
        "post" => Some(Method::POST),
        "head" => Some(Method::HEAD),
        "patch" => Some(Method::PATCH),
        "delete" => Some(Method::DELETE),
        "options" => Some(Method::OPTIONS),
        _ => None,
    }
}

fn map_part(part: &str) -> Option<ResponsePart> {
    match part.to_lowercase().as_str() {
        "header" => Some(ResponsePart::Header),
        "body" => Some(ResponsePart::Body),
        "response" => Some(ResponsePart::Response),
        "all" => Some(ResponsePart::All),
        "raw" => Some(ResponsePart::Raw),
        _ => None,
    }
}

fn map_condition(condition: &str) -> Option<Condition> {
    match condition.to_lowercase().as_str() {
        "or" => Some(Condition::OR),
        "and" => Some(Condition::AND),
        _ => None,
    }
}

fn map_matcher_type(matcher_type: &str) -> Option<MatcherType> {
    match matcher_type.to_lowercase().as_str() {
        "word" => Some(MatcherType::Word(vec![])),
        "dsl" => Some(MatcherType::DSL(vec![])),
        "regex" => Some(MatcherType::Regex(vec![])),
        "status" => Some(MatcherType::Status(vec![])),
        _ => None,
    }
}

fn validate_fields(fields: &[(Option<&str>, &str)]) -> Result<(), TemplateError> {
    for (field, name) in fields {
        if field.is_none() {
            return Err(TemplateError::MissingField((*name).to_string()));
        }
    }
    Ok(())
}

pub fn parse_info(yaml: &Yaml) -> Result<Info, TemplateError> {
    let info_name = yaml["name"].as_str();
    let info_author = yaml["author"].as_str();
    let info_description = yaml["description"].as_str();
    let info_severity = yaml["severity"].as_str();

    validate_fields(&[
        (info_name, "name"),
        (info_author, "author"),
        (info_severity, "severity"),
    ])?;

    let description = if let Some(desc) = info_description {
        desc.to_string()
    } else {
        String::new()
    };

    let severity = map_severity(info_severity.unwrap());
    if severity.is_none() {
        return Err(TemplateError::InvalidValue("Severity".into()));
    }

    let references = if yaml["reference"].is_array() {
        yaml["reference"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect()
    } else if yaml["reference"].as_str().is_some() {
        yaml["reference"]
            .as_str()
            .unwrap()
            .split_terminator('\n')
            .map(|item| item.to_string())
            .collect()
    } else {
        vec![]
    };

    let tags = if yaml["tags"].is_badvalue() {
        vec![]
    } else {
        yaml["tags"]
            .as_str()
            .unwrap()
            .split(',')
            .map(|item| item.to_string())
            .collect()
    };

    Ok(Info {
        name: info_name.unwrap().into(),
        author: info_author.unwrap().into(),
        description,
        severity: severity.unwrap(),
        reference: references,
        tags,
    })
}

pub fn parse_matcher(
    yaml: &Yaml,
    matchers_condition: Condition,
    regex_cache: &mut RegexCache,
) -> Result<Option<Matcher>, TemplateError> {
    let matcher_part = yaml["part"].as_str();
    let matcher_type = yaml["type"].as_str();
    let matcher_name = yaml["name"].as_str();
    validate_fields(&[(matcher_type, "type")])?;

    let r#type = map_matcher_type(matcher_type.unwrap());
    if r#type.is_none() {
        return Err(TemplateError::InvalidValue("type".into()));
    }

    let mut matcher_type = r#type.unwrap();

    let part = {
        let part_mat = match matcher_part {
            Some(match_part) => map_part(match_part),
            None => Some(ResponsePart::Body),
        };
        if part_mat.is_none() {
            // Mather part is not required if matcher type is DSL
            // We also currently ignore missing parts if the match is optional either way
            if matchers_condition == Condition::OR || matches!(matcher_type, MatcherType::DSL(_)) {
                return Ok(None);
            } else {
                return Err(TemplateError::InvalidValue("part".into()));
            }
        }
        part_mat.unwrap()
    };

    let condition = if yaml["condition"].as_str().is_some() {
        match map_condition(yaml["condition"].as_str().unwrap()) {
            Some(condition) => condition,
            None => return Err(TemplateError::InvalidValue("condition".into())),
        }
    } else {
        Condition::OR
    };

    let negative = yaml["negative"].as_bool().unwrap_or(false);
    let internal = yaml["internal"].as_bool().unwrap_or(false);
    let group = yaml["group"].as_i64();

    match &mut matcher_type {
        MatcherType::Word(words) => {
            let words_list = yaml["words"].as_vec();
            if words_list.is_none() {
                return Err(TemplateError::MissingField("words".into()));
            }
            let mut words_strings: Vec<String> = words_list
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect();
            words.append(&mut words_strings);
        }
        MatcherType::DSL(dsls) => {
            let dsl_list = yaml["dsl"].as_vec();
            if dsl_list.is_none() {
                return Err(TemplateError::MissingField("dsl".into()));
            }
            let dsl_list = dsl_list.unwrap();
            let mut dsl_strings: Vec<CompiledExpression> = dsl_list
                .iter()
                .flat_map(|item| compile_expression(item.as_str().unwrap()))
                .collect();
            if dsl_strings.len() != dsl_list.len() {
                let failed = dsl_list
                    .iter()
                    .filter_map(|item| {
                        if compile_expression(item.as_str().unwrap()).is_err() {
                            Some(TemplateError::InvalidDSL(
                                item.as_str().unwrap().to_string(),
                            ))
                        } else {
                            None
                        }
                    })
                    .next();
                return Err(failed.unwrap());
            }
            dsls.append(&mut dsl_strings);
        }
        MatcherType::Regex(regexes) => {
            let regex_list = yaml["regex"].as_vec();
            if regex_list.is_none() {
                return Err(TemplateError::MissingField("regex".into()));
            }
            let regex_strings: Vec<String> = regex_list
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect();

            let patterns: Result<Vec<u32>, _> = regex_strings
                .iter()
                .map(|patt| regex_cache.insert(patt))
                .collect();

            if patterns.is_err() {
                let err = regex_strings
                    .iter()
                    .find(|patt| regex_cache.insert(patt).is_err()) // regex_cache.insert idempotent
                    .cloned()
                    .unwrap();
                return Err(TemplateError::InvalidValue(format!(
                    "Could not parse regex, parse output:\n{}",
                    err
                )));
            }

            *regexes = patterns.unwrap()
        }
        MatcherType::Status(statuses) => {
            let status_list = yaml["status"].as_vec();
            if status_list.is_none() {
                return Err(TemplateError::MissingField("status".into()));
            }
            let mut status_values: Vec<u32> = status_list
                .unwrap()
                .iter()
                .map(|item| item.as_i64().unwrap() as u32)
                .collect();
            statuses.append(&mut status_values);
        }
    }

    let name = matcher_name.map(|name| name.to_string());

    Ok(Some(Matcher {
        part,
        condition,
        r#type: matcher_type,
        group,
        negative,
        internal,
        name,
    }))
}

pub fn parse_http(yaml: &Yaml, regex_cache: &mut RegexCache) -> Result<HttpRequest, TemplateError> {
    let redirects = yaml["redirects"].as_bool();
    let host_redirects = yaml["host-redirects"].as_bool();
    let max_redirects = yaml["max-redirects"].as_i64();
    let http_method = yaml["method"].as_str();
    let http_body = yaml["body"].as_str();
    let http_matchers = yaml["matchers"].as_vec();
    let http_extractors = yaml["extractors"].as_vec();

    let follow_redirects =
        redirects.is_some_and(|val| val) || host_redirects.is_some_and(|val| val);
    let max_redirects = max_redirects.map(|val| val as u32);

    if http_matchers.is_none() {
        return Err(TemplateError::MissingField("matchers".into()));
    }

    let method = if http_method.is_some() {
        let method_ret = map_method(http_method.unwrap());
        if method_ret.is_none() {
            return Err(TemplateError::InvalidValue("method".into()));
        }
        method_ret.unwrap()
    } else {
        Method::GET
    };

    let body = if let Some(body) = http_body {
        body.to_string()
    } else {
        String::new()
    };

    let matchers_condition = if yaml["matchers-condition"].is_badvalue() {
        Condition::OR
    } else {
        match map_condition(yaml["matchers-condition"].as_str().unwrap()) {
            Some(condition) => condition,
            None => return Err(TemplateError::InvalidValue("matchers-condition".into())),
        }
    };

    let matchers_parsed: Vec<_> = http_matchers
        .unwrap()
        .iter()
        .map(|item| parse_matcher(item, matchers_condition, regex_cache))
        .collect();

    if matchers_parsed.iter().any(Result::is_err) {
        if matchers_condition == Condition::AND {
            return Err(matchers_parsed
                .into_iter()
                .find(Result::is_err)
                .unwrap()
                .unwrap_err());
        } else {
            debug!("matcher failed, but was optional:");
            matchers_parsed
                .iter()
                .filter(|item| item.is_err())
                .for_each(|failed| debug!("{:?}", failed));
        }
    }

    let matchers = matchers_parsed.into_iter().flatten().flatten().collect();

    let extractors = if http_extractors.is_some() {
        let extractors_parsed: Vec<_> = http_extractors
            .unwrap()
            .iter()
            .map(|item| parse_matcher(item, matchers_condition, regex_cache))
            .collect();
        if extractors_parsed.iter().any(Result::is_err) {
            return Err(extractors_parsed
                .into_iter()
                .find(Result::is_err)
                .unwrap()
                .unwrap_err());
        }
        extractors_parsed
            .into_iter()
            .flatten()
            .filter_map(|item| {
                if let Some(matcher) = item {
                    Some(Extractor {
                        r#type: matcher.r#type,
                        group: matcher.group,
                        internal: matcher.internal,
                        name: matcher.name,
                        part: matcher.part,
                    })
                } else {
                    None
                }
            })
            .collect()
    } else {
        vec![]
    };

    // TODO: make generic array/(string edge case) iterator thingy for these
    let mut requests = if yaml["path"].is_array() {
        yaml["path"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|item| HttpReq {
                method,
                body: body.clone(),
                path: item.as_str().unwrap().to_string(),
                raw: String::new(),
                headers: Vec::new(),
                follow_redirects,
                max_redirects,
            })
            .collect()
    } else if yaml["path"].as_str().is_some() {
        yaml["path"]
            .as_str()
            .unwrap()
            .split_terminator('\n')
            .map(|item| HttpReq {
                method,
                body: body.clone(),
                path: item.to_string(),
                raw: String::new(),
                headers: Vec::new(),
                follow_redirects,
                max_redirects,
            })
            .collect()
    } else {
        vec![]
    };

    let mut raw = if yaml["raw"].is_array() {
        yaml["raw"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|item| HttpReq {
                method,
                body: body.clone(),
                path: String::new(),
                raw: item.as_str().unwrap().to_string(),
                headers: Vec::new(),
                follow_redirects,
                max_redirects,
            })
            .collect()
    } else if yaml["raw"].as_str().is_some() {
        vec![HttpReq {
            method,
            body: body.clone(),
            path: String::new(),
            raw: yaml["raw"].as_str().unwrap().into(),
            headers: Vec::new(),
            follow_redirects,
            max_redirects,
        }]
    } else {
        vec![]
    };

    let headers = if yaml["headers"].as_hash().is_some() {
        if yaml["headers"]
            .as_hash()
            .unwrap()
            .iter()
            .any(|(key, value)| key.as_str().is_none() || value.as_str().is_none())
        {
            return Err(TemplateError::InvalidValue(
                "Invalid headers key or value".into(),
            ));
        }
        yaml["headers"]
            .as_hash()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                (
                    key.as_str().unwrap().to_string(),
                    value.as_str().unwrap().to_string(),
                )
            })
            .collect()
    } else {
        vec![]
    };

    requests.append(&mut raw);

    let flattened_headers: Vec<String> = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();

    requests
        .iter_mut()
        .for_each(|req| req.headers = flattened_headers.clone());

    Ok(HttpRequest {
        matchers_condition,
        matchers,
        extractors,
        path: requests,
    })
}

fn parse_variables(yaml: &Yaml) -> Vec<(String, Value)> {
    let mut variables = Vec::new();

    let hash = yaml.as_hash().unwrap();

    for (k, v) in hash {
        if k.is_array() || v.is_array() {
            // TODO: Array support required in DSL
            continue;
        }
        let key = k.as_str().unwrap();
        let value = v.as_str().unwrap();
        if get_bracket_pattern().is_match(value) {
            // TODO: Store compiled expression for running right before template is executed
        } else {
            variables.push((key.to_string(), Value::String(value.to_string())));
        }
    }

    variables
}

pub fn load_template(file: &str, regex_cache: &mut RegexCache) -> Result<Template, TemplateError> {
    let template_yaml = &load_yaml_from_file(file)?[0];

    if template_yaml["info"].is_badvalue() {
        return Err(TemplateError::MissingField("info".into()));
    }
    if template_yaml["id"].is_badvalue() {
        return Err(TemplateError::MissingField("id".into()));
    }
    let id = template_yaml["id"].as_str();

    let info = parse_info(&template_yaml["info"])?;

    // TODO: Handle flow, seems to be DSL based, with a functon called http(idx: int) that returns a boolean
    // for if that http request (defined right below) matched
    // EDIT: The flow is actually JavaScript, which we don't really care for, HOWEVER, most of them should be parseable by us
    // e.g. flow(1) && flow(2) ...
    if !template_yaml["flow"].is_badvalue() {
        if template_yaml["flow"].as_str().is_some() {
            let dsl = compile_expression(template_yaml["flow"].as_str().unwrap());
            //println!("{:?} - {}", dsl, template_yaml["flow"].as_str().unwrap());
        } else {
            return Err(TemplateError::InvalidValue("flow".into()));
        }
        return Err(TemplateError::InvalidYaml);
    }

    let http_parsed = if template_yaml["http"].is_badvalue() {
        vec![]
    } else {
        template_yaml["http"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|yaml| parse_http(yaml, regex_cache))
            .collect()
    };

    if http_parsed.iter().any(Result::is_err) {
        return Err(http_parsed
            .into_iter()
            .find(Result::is_err)
            .unwrap()
            .unwrap_err());
    }

    let http = http_parsed.into_iter().flatten().collect();

    let variables = if template_yaml["variables"].is_hash() {
        parse_variables(&template_yaml["variables"])
    } else {
        vec![]
    };

    Ok(Template {
        id: id.unwrap().into(),
        http,
        info,
        variables,
    })
}

pub struct TemplateLoader {
    pub loaded_templates: Vec<Template>,
    pub cache: Cache,
    pub regex_cache: RegexCache,
}

impl TemplateLoader {
    pub fn len(&self) -> usize {
        self.loaded_templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn load_from_path(path: &str) -> Self {
        let mut total = 0;
        let mut success = 0;

        let mut loaded_templates = Vec::new();
        let mut regex_cache = RegexCache::new();

        for entry in WalkDir::new(path).into_iter().flatten() {
            if entry.file_type().is_file()
                && entry.path().extension().is_some()
                && (entry.path().extension().unwrap() == "yml"
                    || entry.path().extension().unwrap() == "yaml")
            {
                let template = load_template(entry.path().to_str().unwrap(), &mut regex_cache);
                if template.is_ok() {
                    success += 1;
                    loaded_templates.push(template.unwrap());
                } else {
                    debug!("{:?} - {}", template, entry.path().to_str().unwrap());
                }
                total += 1;
            }
        }
        debug!(
            "Successfully loaded template ratio: {}/{} - {:.2}%",
            success,
            total,
            (success as f32 / total as f32) * 100.0
        );

        let mut tokens: HashMap<CacheKey, u16> = HashMap::new();
        for template in &loaded_templates {
            for http in &template.http {
                for request in &http.path {
                    tokens
                        .entry(CacheKey(
                            request.method,
                            request.headers.clone(),
                            request.path.clone(),
                        ))
                        .and_modify(|val| *val += 1)
                        .or_insert(1);
                }
            }
        }
        let keys: Vec<CacheKey> = tokens.keys().cloned().collect();
        for key in keys {
            if *tokens.get(&key).unwrap() == 1 {
                tokens.remove(&key);
            }
        }
        let cache = Cache::new(tokens);
        regex_cache.finalize();
        Self {
            cache,
            regex_cache,
            loaded_templates,
        }
    }
}
