use std::time::Duration;
use std::{sync::Mutex, time::Instant};

use clap::Parser;
use photon::template_executor::{ExecutionOptions, ScanError};
use photon::{health_check, set_config};
use photon::{template_executor::TemplateExecutor, template_loader::TemplateLoader};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long, default_value_t = String::from("nuclei-templates"))]
    templates: String,

    #[arg(short, long, default_value_t = false, action)]
    verbose: bool,

    #[arg(short, long, default_value_t = false, action)]
    debug: bool,

    #[arg(short, long, default_value_t = false, action)]
    stats: bool,

    #[arg(short = 'U', long)]
    user_agent: Option<String>,

    #[arg(short = 'H', long)]
    header: Option<Vec<String>>,
}

fn main() {
    let args = Args::parse();

    set_config(photon::Config {
        verbose: args.verbose,
        debug: args.debug,
    });

    let templ_loader = TemplateLoader::load_from_path(&args.templates);

    let base_url = &args.url;

    if let Err(err) = health_check(base_url, Duration::from_secs(15)) {
        println!("Healthcheck failed: {}", err.description());
        return;
    }

    let last_reqs = Mutex::from(0);
    let stopwatch = Mutex::from(Instant::now());

    let template_len = templ_loader.len();

    if template_len == 0 {
        println!("No templates loaded!")
    }

    let mut executor = TemplateExecutor::from(templ_loader);

    let mut options = ExecutionOptions::default();

    if let Some(headers) = args.header {
        for header in headers {
            options.add_header(&header);
        }
    }
    if let Some(user_agent) = args.user_agent {
        options.set_user_agent(&user_agent);
    }

    executor.set_options(options);
    executor.set_callbacks(
        |_, i, reqs| {
            let mut locked_stopwatch = stopwatch.lock().unwrap();
            let mut locked_reqs = last_reqs.lock().unwrap();
            if args.stats && locked_stopwatch.elapsed().as_secs_f32() > 20.0 {
                println!(
                    "RPS: {}, Template: {}/{}, Requests: {}",
                    (reqs - *locked_reqs) as f32 / locked_stopwatch.elapsed().as_secs_f32(),
                    i,
                    template_len,
                    reqs
                );
                *locked_reqs = reqs;
                *locked_stopwatch = Instant::now();
            }
        },
        |template, res| {
            if let Some(name) = &res.name {
                println!(
                    "Matched: [{}] {}:{}",
                    template.info.severity.colored_string(),
                    template.id,
                    name
                );
            } else {
                println!(
                    "Matched: [{}] {}",
                    template.info.severity.colored_string(),
                    template.id
                );
            }
        },
        || true,
    );

    let res = executor.execute(base_url);
    if let Err(err) = res {
        let err_msg = match err {
            ScanError::MissingScheme => "Missing URL Scheme",
            ScanError::UrlParseError => "Error parsing URL",
        };
        println!("ERROR: {err_msg}");
    } else {
        println!("Total requests: {}", executor.get_total_reqs());
    }
}
