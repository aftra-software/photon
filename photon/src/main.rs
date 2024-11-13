mod cache;
mod http;
mod template;
mod template_loader;

use core::str;
use std::{
    fs,
    rc::Rc,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use clap::Parser;
use curl::easy::Easy2;
use http::BRACKET_PATTERN;
use md5::{Digest, Md5};
use photon_dsl::{
    dsl::{bytecode_to_binary, compile_bytecode, DSLStack, Value},
    parser::do_parsing,
    set_config, DslFunc, GLOBAL_FUNCTIONS,
};
use regex::Regex;
use rustc_hash::FxHashMap;
use template::{Collector, Context};
use template_loader::TemplateLoader;
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
    let _ = BRACKET_PATTERN.set(Mutex::from(Regex::new("\\{\\{[^{}]*}}").unwrap()));

    let args = Args::parse();

    let _ = CONFIG.set(Config {
        verbose: args.verbose,
        debug: args.debug,
    });

    // Set same config in DSL lib
    // TODO: make config more similar to CURL, where we do things like
    // photon_dsl::set_debug(true)
    set_config(photon_dsl::Config {
        verbose: args.verbose,
        debug: args.debug,
    });

    let now = Instant::now();

    let mut functions: FxHashMap<String, DslFunc> = FxHashMap::default();

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

    GLOBAL_FUNCTIONS.set(functions).map_err(|_| ()).unwrap();

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
    let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));

    let mut reqs = 0;
    let mut last_reqs = 0;
    let mut stopwatch = Instant::now();

    let ctx = Rc::from(Mutex::from(Context {
        variables: FxHashMap::default(),
        parent: None,
    }));
    // TODO: Should this be handled inside of `http.rs`?
    {
        let parsed: Result<Url, _> = base_url.parse();
        if let Ok(url) = parsed {
            if let Some(hostname) = url.host_str() {
                let mut locked: std::sync::MutexGuard<'_, Context> = ctx.lock().unwrap();
                locked.insert_str("hostname", hostname);
                locked.insert_str("Hostname", hostname);
            }
        }
        ctx.lock().unwrap().insert_str("BaseURL", base_url);
    }

    let template_len = templates.loaded_templates.len();

    if template_len == 0 {
        println!("No templates loaded!")
    }

    for (i, template) in templates.loaded_templates.iter().enumerate() {
        template.execute(
            base_url,
            &mut curl,
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
