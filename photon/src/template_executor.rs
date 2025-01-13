// Manages template execution state

use std::{rc::Rc, sync::Mutex};

use curl::easy::Easy2;
use rand::distributions::{Alphanumeric, DistString};
use rustc_hash::FxHashMap;
use url::Url;

use crate::{
    cache::{Cache, RegexCache},
    template::{Collector, Context, Template},
    template_loader::TemplateLoader,
};

pub struct TemplateExecutor<T, K, C>
where
    T: Fn(&Template, u32, u32),
    K: Fn(&Template, Option<String>),
    C: Fn() -> bool,
{
    pub templates: Vec<Template>,
    ctx: Rc<Mutex<Context>>,
    total_reqs: u32,
    cache: Cache,
    regex_cache: RegexCache,
    template_callback: Option<T>,
    match_callback: Option<K>,
    continue_predicate: Option<C>,
}

impl<T, K, C> TemplateExecutor<T, K, C>
where
    T: Fn(&Template, u32, u32),
    K: Fn(&Template, Option<String>),
    C: Fn() -> bool,
{
    pub fn from(templ_loader: TemplateLoader) -> Self {
        Self {
            ctx: Rc::from(Mutex::from(Context {
                variables: FxHashMap::default(),
                parent: None,
            })),
            total_reqs: 0,
            templates: templ_loader.loaded_templates,
            cache: templ_loader.cache,
            regex_cache: templ_loader.regex_cache,
            template_callback: None,
            match_callback: None,
            continue_predicate: None,
        }
    }

    // Usess more memory than `from` since it copies the TemplateLoader
    pub fn from_ref(templ_loader: &TemplateLoader) -> Self {
        Self {
            ctx: Rc::from(Mutex::from(Context {
                variables: FxHashMap::default(),
                parent: None,
            })),
            total_reqs: 0,
            templates: templ_loader.loaded_templates.clone(),
            cache: templ_loader.cache.clone(),
            regex_cache: templ_loader.regex_cache.clone(),
            template_callback: None,
            match_callback: None,
            continue_predicate: None,
        }
    }

    pub fn get_total_reqs(&self) -> u32 {
        self.total_reqs
    }

    pub fn set_callbacks(
        &mut self,
        template_callback: T,
        match_callback: K,
        continue_predicate: C,
    ) {
        self.template_callback = Some(template_callback);
        self.match_callback = Some(match_callback);
        self.continue_predicate = Some(continue_predicate);
    }

    pub fn execute_from(&mut self, base_url: &str, from: usize) {
        let mut curl = Easy2::new(Collector(Vec::new(), Vec::new()));
        if base_url.starts_with("https") {
            // Manually find and set CA certificates, solves a lot of issues with statically linked libcurl.
            let r = openssl_probe::probe();

            // TODO: Do additional validation to make sure we don't run into the case where
            // CURL can find the certs but openssl_probe can't.
            curl.capath(
                r.cert_dir
                    .expect("Unable to find certificate, cannot continue with HTTPS"),
            )
            .unwrap();
        }

        {
            let parsed: Result<Url, _> = base_url.parse();
            if let Ok(url) = parsed {
                let mut locked: std::sync::MutexGuard<'_, Context> = self.ctx.lock().unwrap();
                if let Some(port) = url.port_or_known_default() {
                    locked.insert_int("Port", port as i64);
                    if let Some(host) = url.host_str() {
                        let hostname = format!("{host}:{port}");
                        locked.insert_str("Hostname", &hostname);
                    }
                }
                if let Some(hostname) = url.host_str() {
                    locked.insert_str("Host", hostname);
                }
                locked.insert_str("Scheme", url.scheme());
                locked.insert_str("Path", url.path());
            }
            // Base URL is the URL passed in, except documented as full url? but full url != base url
            // So for sanity sake we define Root and Base url as the same.
            self.ctx.lock().unwrap().insert_str("BaseURL", base_url);
            self.ctx.lock().unwrap().insert_str("RootURL", base_url);
        }

        for (i, template) in self.templates.iter().enumerate().skip(from) {
            // Some random strings, they're static per template, see https://github.com/projectdiscovery/nuclei/blob/358249bdb4e2f87a7203166ae32b34de0f57b715/pkg/templates/compile.go#L293
            self.ctx.lock().unwrap().insert_str(
                "randstr",
                &Alphanumeric.sample_string(&mut rand::thread_rng(), 27),
            );

            // TODO: Do we want to support arbitrary many random strings?
            // randstr_6 is the highest being used by any template
            for i in 0..6 {
                self.ctx.lock().unwrap().insert_str(
                    &format!("randstr_{}", i + 1),
                    &Alphanumeric.sample_string(&mut rand::thread_rng(), 27),
                );
            }

            let cont = template.execute(
                base_url,
                &mut curl,
                self.ctx.clone(), // Cheap reference clone
                &mut self.total_reqs,
                &mut self.cache,
                &self.regex_cache,
                &self.match_callback,
                &self.continue_predicate,
            );
            if self.template_callback.is_some() {
                self.template_callback.as_ref().unwrap()(template, i as u32, self.total_reqs);
            }
            if !cont {
                break;
            }
        }
    }

    pub fn execute(&mut self, base_url: &str) {
        self.execute_from(base_url, 0);
    }
}
