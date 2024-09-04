mod cache;
mod dsl;
mod http;
mod template;
mod template_loader;

use std::{
    collections::HashMap,
    fs,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use clap::Parser;
use dsl::{bytecode_to_binary, compile_bytecode, parse_expr, parse_tokens, DSLStack, Value};
use http::IGNORE_PATTERN;
use md5::{Digest, Md5};
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

    let now = Instant::now();
    let functions = ["md5", "test_function"]
        .iter()
        .map(|item| item.to_string())
        .collect();
    let tokens = parse_tokens(fs::read_to_string("test.dsl").unwrap(), functions);
    //println!("Tokenizer output: {:?}", tokens);

    if let Ok(toks) = tokens {
        let ast = parse_expr(&toks);
        println!("AST output: {:?}", ast);

        let bytecode = compile_bytecode(ast);
        println!("Compiled expression: {:?}", bytecode);
        println!(
            "Took: {:.4} ms",
            now.elapsed().as_nanos() as f64 / 1_000_000.0
        );
        if let Err(err) = fs::write("test.compiled", bytecode_to_binary(&bytecode)) {
            println!("Error writing bytecode: {}", err);
        }
        let res = bytecode.execute(
            HashMap::from([("input".into(), Value::String("Hello".into()))]),
            HashMap::from([("md5".into(), |stack: &mut DSLStack| {
                let inp = stack.pop_string()?;
                let hash = base16ct::lower::encode_string(&Md5::digest(inp));
                stack.push(Value::String(hash));
                Ok(())
            })]),
        );
        println!("Output from executed bytecode: {:?}", res);
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
