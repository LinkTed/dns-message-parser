use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::ops::Deref;

use regex::Regex;

#[derive(Debug, PartialEq)]
pub enum DomainError {
    LabelLength,
    DomainNameLength,
    Regex,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct DomainName {
    pub(crate) domain_name: String,
}

impl DomainName {
    pub fn append_label(&mut self, label: &str) -> Result<(), DomainError> {
        lazy_static! {
            static ref LABEL_REGEX: Regex = Regex::new(r"[^-.\x00][^.\x00]*").unwrap();
        }

        let label_length = label.len();
        if label_length >= 64 {
            return Err(DomainError::LabelLength);
        }

        let domain_name_length = self.domain_name.len();
        if domain_name_length + label_length >= 256 {
            return Err(DomainError::DomainNameLength);
        }

        if LABEL_REGEX.is_match(label) {
            if &self.domain_name == "." {
                self.domain_name.insert_str(0, label);
            } else {
                self.domain_name.push_str(label);
                self.domain_name.push('.');
            }
            Ok(())
        } else {
            Err(DomainError::Regex)
        }
    }
}

impl TryFrom<&str> for DomainName {
    type Error = DomainError;

    fn try_from(string: &str) -> Result<Self, DomainError> {
        let string_relativ = if let Some(string_relativ) = string.strip_suffix('.') {
            string_relativ
        } else {
            string
        };

        let mut domain_name = DomainName::default();
        for label in string_relativ.split('.') {
            domain_name.append_label(label)?;
        }
        Ok(domain_name)
    }
}

impl Default for DomainName {
    fn default() -> Self {
        DomainName {
            domain_name: ".".to_string(),
        }
    }
}

impl Deref for DomainName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.domain_name
    }
}

impl Display for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.domain_name)
    }
}
