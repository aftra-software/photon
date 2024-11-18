// Manages template execution state

use std::{rc::Rc, sync::Mutex};

use curl::easy::Easy2;
use rustc_hash::FxHashMap;
use url::Url;

use crate::{
    cache::{Cache, RegexCache},
    template::{Collector, Context, Template},
    template_loader::TemplateLoader,
};

pub struct TemplateExecutor<T>
where
    T: Fn(&Template, u32, u32),
{
    pub templates: Vec<Template>,
    ctx: Rc<Mutex<Context>>,
    total_reqs: u32,
    cache: Cache,
    regex_cache: RegexCache,
    template_callback: Option<T>,
    match_callback: Option<T>,
}

impl<T> TemplateExecutor<T>
where
    T: Fn(&Template, u32, u32),
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
        }
    }

	pub fn get_total_reqs(&self) -> u32 {
		self.total_reqs
	}

    pub fn set_template_callback(&mut self, f: T) {
        self.template_callback = Some(f);
    }

    pub fn execute(&mut self, base_url: &str) {
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
            self.ctx.lock().unwrap().insert_str("BaseURL", base_url);
        }

        for (i, template) in self.templates.iter().enumerate() {
            template.execute(
                base_url,
                &mut curl,
                self.ctx.clone(), // Cheap reference clone
                &mut self.total_reqs,
                &mut self.cache,
                &self.regex_cache,
            );
            if self.template_callback.is_some() {
                self.template_callback.as_ref().unwrap()(template, i as u32, self.total_reqs);
            }
        }
    }
}
