use std::{sync::Mutex, time::Instant};

use clap::Parser;
use photon::{initialize, set_config};
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
}

fn main() {
    let args = Args::parse();

    set_config(photon::Config {
        verbose: args.verbose,
        debug: args.debug,
    });

    initialize();

    let templ_loader = TemplateLoader::load_from_path(&args.templates);

    let base_url = &args.url;

    let last_reqs = Mutex::from(0);
    let stopwatch = Mutex::from(Instant::now());

    let template_len = templ_loader.len();

    if template_len == 0 {
        println!("No templates loaded!")
    }

    let mut executor = TemplateExecutor::from(templ_loader);
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
        |template, name| {
            if name.is_some() {
                println!(
                    "Matched: [{}] {}:{}",
                    template.info.severity.colored_string(),
                    template.id,
                    name.unwrap()
                );
            } else {
                println!(
                    "Matched: [{}] {}",
                    template.info.severity.colored_string(),
                    template.id
                );
            }
        },
    );

    executor.execute(base_url);

    println!("Total requests: {}", executor.get_total_reqs());
}
