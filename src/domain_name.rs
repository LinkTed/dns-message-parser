use std::fmt::{Display, Formatter, Result as FmtResult};

use regex::Regex;

#[derive(Debug, Getters, PartialEq, Clone, Eq, Hash)]
pub struct DomainName {
    #[get = "pub with_prefix"]
    pub(crate) domain_name: String,
}

impl DomainName {
    pub fn append_label(&mut self, label: &str) -> bool {
        lazy_static! {
            static ref LABEL_REGEX: Regex = Regex::new(r"[^-.\x00][^.\x00]*").unwrap();
        }

        let label_length = label.len();
        if label_length >= 64 {
            return false;
        }

        let domain_name_length = self.domain_name.len();
        if domain_name_length + label_length >= 256 {
            return false;
        }

        if LABEL_REGEX.is_match(label) {
            if &self.domain_name == "." {
                self.domain_name.insert_str(0, label);
            } else {
                self.domain_name.push_str(label);
                self.domain_name.push('.');
            }
            true
        } else {
            false
        }
    }
}

impl Default for DomainName {
    fn default() -> Self {
        DomainName {
            domain_name: ".".to_string(),
        }
    }
}

impl Display for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.domain_name)
    }
}
