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
        {
            let parsed: Result<Url, _> = base_url.parse();
            if let Ok(url) = parsed {
                if let Some(hostname) = url.host_str() {
                    let mut locked: std::sync::MutexGuard<'_, Context> = self.ctx.lock().unwrap();
                    locked.insert_str("hostname", hostname);
                    locked.insert_str("Hostname", hostname);
                }
            }
            // Base URL is the URL passed in, except documented as full url? but full url != base url
            // So for sanity sake we define Root and Base url as the same.
            self.ctx.lock().unwrap().insert_str("BaseURL", base_url);
            self.ctx.lock().unwrap().insert_str("RootURL", base_url);

            // Some random strings
            // TODO: Do we want to support arbitrary many random strings?
            self.ctx.lock().unwrap().insert_str(
                "randstr",
                &Alphanumeric.sample_string(&mut rand::thread_rng(), 27),
            );
            self.ctx.lock().unwrap().insert_str(
                "randstr_1",
                &Alphanumeric.sample_string(&mut rand::thread_rng(), 27),
            );
            self.ctx.lock().unwrap().insert_str(
                "randstr_2",
                &Alphanumeric.sample_string(&mut rand::thread_rng(), 27),
            );
        }

        for (i, template) in self.templates.iter().enumerate().skip(from) {
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
