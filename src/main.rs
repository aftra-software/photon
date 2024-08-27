use std::{collections::HashMap, sync::Mutex, time::Instant};

use http::{HttpResponse, IGNORE_PATTERN};
use regex::Regex;
use template::{Condition, Method, REGEX_CACHE};
use template_loader::load_template;
use ureq::Agent;
use walkdir::WalkDir;

mod http;
mod template;
mod template_loader;

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    url: String,
}

fn main() {
    let _ = REGEX_CACHE.set(Mutex::from(HashMap::new()));
    let _ = IGNORE_PATTERN.set(Mutex::from(Regex::new("\\{\\{.*}}").unwrap()));

    let args = Args::parse();

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

    let mut allowed_cache: HashMap<(Method, String), u16> = HashMap::new();
    for template in loaded_templates.iter() {
        for http in template.http.iter() {
            for request in http.path.iter() {
                allowed_cache.entry((request.method, request.path.clone())).and_modify(|val| *val += 1).or_insert(1);
            }
        }
    }
    let keys: Vec<(Method, String)> = allowed_cache.keys().cloned().collect();
    for key in keys {
        if *allowed_cache.get(&key).unwrap() == 1 {
            allowed_cache.remove(&key);
        }
    }

    println!("{:?}", allowed_cache);


    let base_url = &args.url;
    let request_agent = Agent::new();

    let mut reqs = 0;
    let mut last_reqs = 0;
    let mut cache: HashMap<(Method, String), Option<HttpResponse>> = HashMap::new();
    let mut stopwatch = Instant::now();

    let template_len = loaded_templates.len();

    for (i, t) in loaded_templates.into_iter().enumerate() {
        let mut skip = false;
        for http in t.http {
            if skip {
                break;
            }
            for req in http.path {
                if stopwatch.elapsed().as_secs_f32() > 10.0 {
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
                let resp = req.do_request(base_url, &request_agent, &mut reqs, &mut cache, &allowed_cache);
                if let Some(body) = resp {
                    let matches = if http.matchers_condition == Condition::OR {
                        http.matchers
                            .iter()
                            .any(|matcher| matcher.matches(&body) && !matcher.internal)
                    } else {
                        http.matchers
                            .iter()
                            .all(|matcher| matcher.matches(&body) && !matcher.internal)
                    };
                    if matches {
                        // TODO: Handle matching better with `http.matchers_condition`

                        println!("Matched: [{}] {}", t.info.severity.to_string(), t.id);
                        skip = true;
                        break;
                    }
                }
            }
        }
    }

    println!("Total requests: {}", reqs);
}
