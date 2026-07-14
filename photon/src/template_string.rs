use std::{
    collections::HashSet,
    fmt::{Display, Formatter},
    sync::OnceLock,
};

use photon_dsl::{dsl::VariableContainer, parser::compile_expression_validated};
use regex::Regex;

use crate::{PhotonContext, get_config, template::Context};

static BRACKET_PATTERN: OnceLock<Regex> = OnceLock::new();

pub(crate) fn get_bracket_pattern() -> &'static Regex {
    BRACKET_PATTERN.get_or_init(|| Regex::new(r"\{\{([^{}]*)}}").unwrap())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TemplateString(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BakeError {
    Unresolved(Vec<String>),
    RecursionLimit,
}

impl Display for BakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unresolved(values) => write!(f, "unresolved values: {}", values.join(", ")),
            Self::RecursionLimit => f.write_str("template interpolation recursion limit reached"),
        }
    }
}

impl std::error::Error for BakeError {}

impl TemplateString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn bake(&self, ctx: &Context, photon_ctx: &PhotonContext) -> Result<String, BakeError> {
        let mut baked = self.0.clone();
        // Bound recursive interpolation so self-referential expressions cannot loop forever.
        for _ in 0..100 {
            let tmp = baked.clone();
            let matches: Vec<_> = get_bracket_pattern().captures_iter(&tmp).collect();

            let mut updated = false;
            for mat in &matches {
                let match_str = mat.get(1).unwrap().as_str();
                // Prefer exact variable names to avoid parsing ambiguity in names such as request-id.
                if let Some(matched) = ctx.get(match_str) {
                    baked.replace_range(mat.get(0).unwrap().range(), &matched.to_string());
                    updated = true;
                    break;
                }

                if let Ok(expr) = compile_expression_validated(match_str, &photon_ctx.functions)
                    && let Ok(ret) = expr.execute(ctx, &photon_ctx.functions)
                {
                    // Replace one expression at a time so repeated random calls remain independent.
                    baked.replace_range(mat.get(0).unwrap().range(), &ret.to_string());
                    updated = true;
                    break;
                }
            }

            if !updated {
                if !matches.is_empty() {
                    let mut unique = matches
                        .iter()
                        .map(|m| m.get(1).unwrap().as_str().to_string())
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    unique.sort();
                    verbose!(
                        "Skipping, {} missing parameters: [{}]",
                        unique.len(),
                        unique.join(", ")
                    );
                    return Err(BakeError::Unresolved(unique));
                }
                return Ok(baked);
            }
        }

        if get_bracket_pattern().is_match(&baked) {
            Err(BakeError::RecursionLimit)
        } else {
            Ok(baked)
        }
    }
}

impl From<String> for TemplateString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for TemplateString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TemplateHeader {
    name: String,
    value: TemplateString,
}

impl TemplateHeader {
    pub fn new(name: impl Into<String>, value: impl Into<TemplateString>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn bake(&self, ctx: &Context, photon_ctx: &PhotonContext) -> Result<String, BakeError> {
        Ok(format!(
            "{}: {}",
            self.name,
            self.value.bake(ctx, photon_ctx)?
        ))
    }
}

#[cfg(test)]
mod tests {
    use rustc_hash::FxHashMap;

    use super::{TemplateHeader, TemplateString};
    use crate::{
        PhotonContext, init_functions,
        template::{Context, ContextScope},
    };

    fn contexts() -> (Context, PhotonContext) {
        photon_dsl::set_config(photon_dsl::Config {
            verbose: false,
            debug: false,
        });
        (
            Context {
                variables: FxHashMap::default(),
                parent: None,
                scope: ContextScope::Global,
            },
            PhotonContext {
                functions: init_functions(),
            },
        )
    }

    #[test]
    fn bakes_variables_and_expressions() {
        let (mut ctx, photon_ctx) = contexts();
        ctx.insert_str("username", "admin");

        let value = TemplateString::from("user={{username}}&hash={{md5('test')}}");
        assert_eq!(
            value.bake(&ctx, &photon_ctx).as_deref(),
            Ok("user=admin&hash=098f6bcd4621d373cade4e832627b4f6")
        );
    }

    #[test]
    fn bakes_header_to_curl_format() {
        let (mut ctx, photon_ctx) = contexts();
        ctx.insert_str("token", "secret");

        let header = TemplateHeader::new("Authorization", "Bearer {{token}}");
        assert_eq!(
            header.bake(&ctx, &photon_ctx).as_deref(),
            Ok("Authorization: Bearer secret")
        );
    }

    #[test]
    fn unresolved_values_do_not_bake() {
        let (ctx, photon_ctx) = contexts();
        assert!(
            TemplateString::from("{{missing}}")
                .bake(&ctx, &photon_ctx)
                .is_err()
        );
    }
}
