mod cache;
mod dsl;
mod http;
mod parser;
mod template;
mod template_loader;

use std::{
    fs,
    rc::Rc,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use clap::Parser;
use dsl::{bytecode_to_binary, compile_bytecode, DSLStack, Value, GLOBAL_FUNCTIONS};
use http::IGNORE_PATTERN;
use md5::{Digest, Md5};
use parser::do_parsing;
use regex::Regex;
use rustc_hash::FxHashMap;
use template::Context;
use template_loader::TemplateLoader;
use ureq::Agent;
use url::Url;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long, default_value_t = String::from("nuclei-templates"))]
    templates: String,

    #[arg(long, default_value_t = String::from("test.dsl"))]
    test: String,

    #[arg(short, long, default_value_t = false, action)]
    verbose: bool,

    #[arg(short, long, default_value_t = false, action)]
    debug: bool,

    #[arg(short, long, default_value_t = false, action)]
    stats: bool,
}

struct Config {
    verbose: bool,
    debug: bool,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

fn main() {
    let _ = IGNORE_PATTERN.set(Mutex::from(Regex::new("\\{\\{[^}]*}}").unwrap()));

    let args = Args::parse();

    let _ = CONFIG.set(Config {
        verbose: args.verbose,
        debug: args.debug,
    });

    let now = Instant::now();

    let mut functions: FxHashMap<
        String,
        Box<dyn Fn(&mut DSLStack) -> Result<(), ()> + Send + Sync>,
    > = FxHashMap::default();

    functions.insert(
        "md5".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            let hash = base16ct::lower::encode_string(&Md5::digest(inp));
            stack.push(Value::String(hash));
            Ok(())
        }),
    );
    functions.insert(
        "regex".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            let patt = stack.pop_string()?;
            let reg = Regex::new(&patt).map_err(|_| ())?;
            stack.push(Value::Boolean(reg.is_match(&inp)));
            Ok(())
        }),
    );
    functions.insert(
        "contains".into(),
        Box::new(|stack: &mut DSLStack| {
            let needle = stack.pop_string()?;
            let haystack = stack.pop_string()?;
            stack.push(Value::Boolean(haystack.contains(&needle)));
            Ok(())
        }),
    );
    functions.insert(
        "tolower".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            stack.push(Value::String(inp.to_lowercase()));
            Ok(())
        }),
    );
    functions.insert(
        "to_lower".into(),
        Box::new(|stack: &mut DSLStack| {
            let inp = stack.pop_string()?;
            stack.push(Value::String(inp.to_lowercase()));
            Ok(())
        }),
    );

    GLOBAL_FUNCTIONS.set(functions).map_err(|_|()).unwrap();

    if CONFIG.get().unwrap().debug {
        let res = do_parsing(&fs::read_to_string(&args.test).unwrap());
        println!("AST output: {:?}", res);

        if let Ok(ast) = res {
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
                &FxHashMap::from_iter([
                    ("input".into(), Value::String("Hello".into())),
                    ("test".into(), Value::Boolean(true)),
                ]),
                GLOBAL_FUNCTIONS.get().unwrap(),
            );
            println!("Output from executed bytecode: {:?}", res);
        }
    }

    let mut templates = TemplateLoader::load_from_path(&args.templates);

    let base_url = &args.url;
    let request_agent = Agent::new();

    let mut reqs = 0;
    let mut last_reqs = 0;
    let mut stopwatch = Instant::now();

    let ctx = Rc::from(Mutex::from(Context {
        variables: FxHashMap::default(),
        parent: None,
    }));
    {
        let parsed: Result<Url, _> = base_url.parse();
        if let Ok(url) = parsed {
            if let Some(hostname) = url.host_str() {
                ctx.lock()
                    .unwrap()
                    .variables
                    .insert("hostname".to_string(), Value::String(hostname.to_string()));
            }
        }
        ctx.lock()
            .unwrap()
            .variables
            .insert("BaseURL".to_string(), Value::String(base_url.to_string()));
    }

    let template_len = templates.loaded_templates.len();
    for (i, template) in templates.loaded_templates.iter().enumerate() {
        template.execute(
            base_url,
            &request_agent,
            ctx.clone(), // Cheap reference clone
            &mut reqs,
            &mut templates.cache,
            &templates.regex_cache,
        );
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
