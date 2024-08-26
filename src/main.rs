use std::{collections::HashMap, sync::Mutex, thread::sleep, time::Duration};

use http::{HttpResponse, IGNORE_PATTERN};
use regex::Regex;
use template::{Condition, Method, REGEX_CACHE};
use template_loader::load_template;
use walkdir::WalkDir;

mod http;
mod template;
mod template_loader;

fn main() {
    let _ = REGEX_CACHE.set(Mutex::from(HashMap::new()));
    let _ = IGNORE_PATTERN.set(Mutex::from(Regex::new("\\{\\{.*}}").unwrap()));

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
                    println!("{:?} - {}", template, entry.path().to_str().unwrap());
                }
                total += 1;
            }
        }
    }
    println!(
        "Success ratio: {}/{} - {:.2}%",
        success,
        total,
        (success as f32 / total as f32) * 100.0
    );
    let base_url = "http://127.0.0.1:8000";

    let mut reqs = 0;
    let mut cache: HashMap<(Method, String), Option<HttpResponse>> = HashMap::new();

    for t in loaded_templates {
        let mut skip = false;
        for http in t.http {
            if skip {
                break;
            }
            for req in http.path {
                let resp = req.do_request(base_url, &mut reqs, &mut cache);
                if let Some(body) = resp {
                    let matches = if http.matchers_condition == Condition::OR {
                        http.matchers.iter().any(|matcher| matcher.matches(&body) && !matcher.internal)
                    } else {
                        http.matchers.iter().all(|matcher| matcher.matches(&body) && !matcher.internal)
                    };
                    if matches {
                        println!("Matched: {}", t.id);
                        skip = true;
                        break;
                    }
                }
            }
        }
    }

    println!("Total requests: {}", reqs);
    sleep(Duration::from_secs_f64(30.0));
}
