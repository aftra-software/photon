mod cache;
mod dsl;
mod http;
mod template;
mod template_loader;

use std::{
    fs,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use clap::Parser;
use dsl::{build_ast, parse_tokens};
use http::IGNORE_PATTERN;
use regex::Regex;
use template_loader::TemplateLoader;
use ureq::Agent;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long, default_value_t = String::from("nuclei-templates"), action)]
    templates: String,

    #[arg(short, long, default_value_t = false, action)]
    verbose: bool,

    #[arg(short, long, default_value_t = false, action)]
    debug: bool,

    #[arg(short, long, default_value_t = true)]
    stats: bool,
}

struct Config {
    verbose: bool,
    debug: bool,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

fn main() {
    let _ = IGNORE_PATTERN.set(Mutex::from(Regex::new("\\{\\{.*}}").unwrap()));

    let args = Args::parse();

    let _ = CONFIG.set(Config {
        verbose: args.verbose,
        debug: args.debug,
    });

    let functions = vec!["md5", "test_function"]
        .iter()
        .map(|item| item.to_string())
        .collect();
    let tokens = parse_tokens(fs::read_to_string("test.dsl").unwrap(), functions);
    println!("Tokenizer output: {:?}", tokens);

    if let Ok(toks) = tokens {
        let ast = build_ast(&toks);
        println!("AST output: {:?}", ast);
    }

    let mut templates = TemplateLoader::load_from_path(&args.templates);

    let base_url = &args.url;
    let request_agent = Agent::new();

    let mut reqs = 0;
    let mut last_reqs = 0;
    let mut stopwatch = Instant::now();

    let template_len = templates.loaded_templates.len();
    for (i, template) in templates.loaded_templates.iter().enumerate() {
        template.execute(base_url, &request_agent, &mut reqs, &mut templates.cache);
        if args.stats && stopwatch.elapsed().as_secs_f32() > 20.0 {
            println!(
                "RPS: {}, Template: {}/{}, Requests: {}",
                (reqs - last_reqs) as f32 / stopwatch.elapsed().as_secs_f32(),
                i,
                template_len,
                reqs
            );
            last_reqs = reqs;
            stopwatch = Instant::now();
        }
    }

    println!("Total requests: {}", reqs);
}
