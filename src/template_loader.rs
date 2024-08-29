use std::{fmt::Debug, fs};

use regex::{Regex, RegexSet};
use yaml_rust2::{Yaml, YamlLoader};

use crate::{
    http::HttpReq,
    template::{
        Condition, HttpRequest, Info, Matcher, MatcherType, Method, RegexType, ResponsePart,
        Severity, Template,
    },
};

#[derive(Debug)]
pub enum TemplateError {
    MissingField(String),
    InvalidValue(String),
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
        "regex" => Some(MatcherType::Regex(RegexType::PatternList(vec![]))),
        "status" => Some(MatcherType::Status(vec![])),
        _ => None,
    }
}

fn validate_fields(fields: &[(Option<&str>, &str)]) -> Result<(), TemplateError> {
    for (field, name) in fields {
        if field.is_none() {
            return Err(TemplateError::MissingField(name.to_string()));
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
        "".to_string()
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
) -> Result<Option<Matcher>, TemplateError> {
    let matcher_part = yaml["part"].as_str();
    let matcher_type = yaml["type"].as_str();
    let matcher_name = yaml["name"].as_str();
    validate_fields(&[(matcher_type, "type")])?;

    let part = {
        let part_mat = match matcher_part {
            Some(match_part) => map_part(match_part),
            None => Some(ResponsePart::Body),
        };
        if part_mat.is_none() {
            if matchers_condition == Condition::OR {
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

    let r#type = map_matcher_type(matcher_type.unwrap());
    if r#type.is_none() {
        return Err(TemplateError::InvalidValue("type".into()));
    }

    let mut matcher_type = r#type.unwrap();

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
            let mut dsl_strings: Vec<String> = dsl_list
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect();
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

            let patterns: Vec<Result<Regex, _>> =
                regex_strings.iter().map(|patt| Regex::new(patt)).collect();

            if patterns.iter().any(|item| item.is_err()) {
                let err = patterns.iter().find(|item| item.is_err()).cloned().unwrap();
                return Err(TemplateError::InvalidValue(format!(
                    "Could not parse regex, parse output: {}",
                    err.unwrap_err()
                )));
            }
            if condition == Condition::OR {
                *regexes = RegexType::Set(RegexSet::new(regex_strings).unwrap());
            } else {
                *regexes = RegexType::PatternList(patterns.iter().flatten().cloned().collect())
            }
        }
        MatcherType::Status(statuses) => {
            let status_list = yaml["status"].as_vec();
            if status_list.is_none() {
                return Err(TemplateError::MissingField("status".into()));
            }
            let mut status_values: Vec<u8> = status_list
                .unwrap()
                .iter()
                .map(|item| item.as_i64().unwrap() as u8)
                .collect();
            statuses.append(&mut status_values);
        }
    }

    let name = match matcher_name {
        Some(name) => Some(name.to_string()),
        None => None,
    };

    Ok(Some(Matcher {
        part,
        condition,
        r#type: matcher_type,
        negative,
        internal,
        name,
    }))
}

pub fn parse_http(yaml: &Yaml) -> Result<HttpRequest, TemplateError> {
    let http_method = yaml["method"].as_str();
    let http_matchers = yaml["matchers"].as_vec();

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
        .map(|item| parse_matcher(item, matchers_condition))
        .collect();

    if matchers_parsed.iter().any(|item| item.is_err()) {
        return Err(matchers_parsed
            .into_iter()
            .find(|item| item.is_err())
            .unwrap()
            .unwrap_err());
    }

    let matchers = matchers_parsed.into_iter().flatten().flatten().collect();

    // TODO: make generic array/(string edge case) iterator thingy for these
    let mut requests = if yaml["path"].is_array() {
        yaml["path"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|item| HttpReq {
                method,
                path: item.as_str().unwrap().to_string(),
                raw: "".into(),
            })
            .collect()
    } else if yaml["path"].as_str().is_some() {
        yaml["path"]
            .as_str()
            .unwrap()
            .split_terminator('\n')
            .map(|item| HttpReq {
                method,
                path: item.to_string(),
                raw: "".into(),
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
                path: "".into(),
                raw: item.as_str().unwrap().to_string(),
            })
            .collect()
    } else if yaml["raw"].as_str().is_some() {
        vec![HttpReq {
            method,
            path: "".into(),
            raw: yaml["raw"].as_str().unwrap().into(),
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

    Ok(HttpRequest {
        matchers_condition,
        matchers,
        headers,
        path: requests,
    })
}

pub fn load_template(file: &str) -> Result<Template, TemplateError> {
    let template_yaml = &load_yaml_from_file(file)?[0];

    if template_yaml["info"].is_badvalue() {
        return Err(TemplateError::MissingField("info".into()));
    }
    if template_yaml["id"].is_badvalue() {
        return Err(TemplateError::MissingField("id".into()));
    }
    let id = template_yaml["id"].as_str();

    let info = parse_info(&template_yaml["info"])?;

    let http_parsed = if template_yaml["http"].is_badvalue() {
        vec![]
    } else {
        template_yaml["http"]
            .as_vec()
            .unwrap()
            .iter()
            .map(parse_http)
            .collect()
    };

    if http_parsed.iter().any(|item| item.is_err()) {
        return Err(http_parsed
            .into_iter()
            .find(|item| item.is_err())
            .unwrap()
            .unwrap_err());
    }

    let http = http_parsed.into_iter().flatten().collect();

    Ok(Template {
        id: id.unwrap().into(),
        http,
        info,
    })
}
