use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::Instant,
};

use cache::{Cache, CacheKey};
use http::IGNORE_PATTERN;
use regex::Regex;
use template::Condition;
use template_loader::load_template;
use ureq::Agent;
use walkdir::WalkDir;

mod cache;
mod http;
mod template;
mod template_loader;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(short, long, default_value_t = true)]
    stats: bool,
}

struct Config {
    verbose: bool,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

fn main() {
    let _ = IGNORE_PATTERN.set(Mutex::from(Regex::new("\\{\\{.*}}").unwrap()));

    let args = Args::parse();

    let _ = CONFIG.set(Config {
        verbose: args.verbose,
    });

    let dir = "nuclei-templates";
    let mut total = 0;
    let mut success = 0;

    let mut loaded_templates = Vec::new();

    for entry_res in WalkDir::new(dir) {
        if let Ok(entry) = entry_res {
            if entry.file_type().is_file()
                && entry.path().extension().is_some()
                && (entry.path().extension().unwrap() == "yml"
                    || entry.path().extension().unwrap() == "yaml")
            {
                let template = load_template(entry.path().to_str().unwrap());
                if template.is_ok() {
                    success += 1;
                    loaded_templates.push(template.unwrap());
                } else {
                    //println!("{:?} - {}", template, entry.path().to_str().unwrap());
                }
                total += 1;
            }
        }
    }
    println!(
        "Successfully loaded template ratio: {}/{} - {:.2}%",
        success,
        total,
        (success as f32 / total as f32) * 100.0
    );

    let mut tokens: HashMap<CacheKey, u16> = HashMap::new();
    for template in loaded_templates.iter() {
        for http in template.http.iter() {
            for request in http.path.iter() {
                tokens
                    .entry(CacheKey(request.method, request.path.clone()))
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

    let base_url = &args.url;
    let request_agent = Agent::new();

    let mut reqs = 0;
    let mut last_reqs = 0;
    let mut cache = Cache::new(tokens);
    let mut stopwatch = Instant::now();

    let template_len = loaded_templates.len();
    for (i, template) in loaded_templates.iter().enumerate() {
        template.execute(base_url, &request_agent, &mut reqs, &mut cache);
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
