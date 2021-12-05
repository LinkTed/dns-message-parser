use crate::{Label, LabelError};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    hash::Hash,
    str::FromStr,
};
use thiserror::Error;

pub const DOMAIN_NAME_MAX_RECURSION: usize = 16;
pub const DOMAIN_NAME_MAX_LENGTH: usize = 256;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum DomainNameError {
    #[error("Domain name is too big: {DOMAIN_NAME_MAX_LENGTH} <= {0}")]
    DomainNameLength(usize),
    #[error("{0}")]
    LabelError(#[from] LabelError),
}

/// Represent a domain name according to [RFC 2181](https://datatracker.ietf.org/doc/html/rfc2181#section-11).
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct DomainName(pub(super) Vec<Label>);

impl DomainName {
    /// Append a label to the domain name.
    ///
    /// If the label cannot be appended then the domain name is not changed.
    /// The label cannot be appended if the domain name would be too big.
    ///
    /// # Example
    /// ```
    /// # use dns_message_parser::DomainName;
    /// let mut domain_name = DomainName::default();
    /// // Prints "."
    /// println!("{}", domain_name);
    ///
    /// domain_name.append_label("example".parse().unwrap()).unwrap();
    /// // Prints "example."
    /// println!("{}", domain_name);
    ///
    /// domain_name.append_label("org".parse().unwrap()).unwrap();
    /// // Prints "example.org."
    /// println!("{}", domain_name);
    /// ```
    pub fn append_label(&mut self, label: Label) -> Result<(), DomainNameError> {
        let label_length = label.len();
        let domain_name_length = if self.0.is_empty() {
            label_length + 1
        } else {
            self.len() + label_length + 1
        };

        if DOMAIN_NAME_MAX_LENGTH <= domain_name_length {
            return Err(DomainNameError::DomainNameLength(domain_name_length));
        }

        self.0.push(label);
        Ok(())
    }

    pub fn len(&self) -> usize {
        let labels = self.0.len();
        if labels == 0 {
            1
        } else {
            let mut length = labels;
            for label in self.0.iter() {
                length += label.len();
            }
            length
        }
    }

    #[inline]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for DomainName {
    type Err = DomainNameError;

    fn from_str(string: &str) -> Result<Self, <Self as FromStr>::Err> {
        let string_relativ = if let Some(string_relativ) = string.strip_suffix('.') {
            string_relativ
        } else {
            string
        };

        let mut domain_name = DomainName::default();
        for label in string_relativ.split('.') {
            let label = label.parse()?;
            domain_name.append_label(label)?;
        }
        Ok(domain_name)
    }
}

impl Display for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if self.is_root() {
            write!(f, ".")
        } else {
            for label in self.0.iter() {
                write!(f, "{}.", label)?;
            }
            Ok(())
        }
    }
}
