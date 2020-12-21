use lazy_static::lazy_static;
use regex::Regex;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result as FmtResult};
use thiserror::Error;

pub const DOMAIN_NAME_MAX_RECURSION: usize = 16;
pub const DOMAIN_NAME_MAX_LABEL_LENGTH: usize = 64;
pub const DOMAIN_NAME_MAX_LENGTH: usize = 256;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum DomainNameError {
    #[error("Label is too big: {DOMAIN_NAME_MAX_LABEL_LENGTH} <= {0}")]
    LabelLength(usize),
    #[error("Domain name is too big: {DOMAIN_NAME_MAX_LENGTH} <= {0}")]
    DomainNameLength(usize),
    #[error("Domain name contains illegal character: {0}")]
    Regex(String),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct DomainName(pub(super) String);

impl DomainName {
    pub fn append_label(&mut self, label: &str) -> Result<(), DomainNameError> {
        lazy_static! {
            static ref LABEL_REGEX: Regex =
                Regex::new(r"^[_0-9a-zA-Z]([_0-9a-zA-Z-]*[_0-9a-zA-Z])?$").unwrap();
        }

        let label_length = label.len();
        if DOMAIN_NAME_MAX_LABEL_LENGTH <= label_length {
            return Err(DomainNameError::LabelLength(label_length));
        }

        let domain_name_length = self.0.len() + label_length;
        if DOMAIN_NAME_MAX_LENGTH <= domain_name_length {
            return Err(DomainNameError::DomainNameLength(domain_name_length));
        }

        if LABEL_REGEX.is_match(label) {
            let label = label.to_lowercase();
            if &self.0 == "." {
                self.0.insert_str(0, &label);
            } else {
                self.0.push_str(&label);
                self.0.push('.');
            }
            Ok(())
        } else {
            Err(DomainNameError::Regex(label.to_string()))
        }
    }
}

impl TryFrom<&str> for DomainName {
    type Error = DomainNameError;

    fn try_from(string: &str) -> Result<Self, DomainNameError> {
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
        DomainName(".".to_string())
    }
}

impl From<DomainName> for String {
    fn from(domain_name: DomainName) -> Self {
        domain_name.0
    }
}

impl PartialEq<&str> for DomainName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == other.to_lowercase()
    }
}

impl Display for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}
