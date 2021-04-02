use super::Class;
use crate::DomainName;
use hex::encode;
use std::convert::{AsRef, TryFrom};
use std::fmt::{Display, Formatter, Result as FmtResult};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum TagError {
    #[error("Tag is empty")]
    Empty,
    #[error("Tag contains illegal character: {0}")]
    IllegalChar(char),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tag(String);

impl TryFrom<String> for Tag {
    type Error = TagError;

    fn try_from(mut tag: String) -> Result<Self, Self::Error> {
        if tag.is_empty() {
            return Err(TagError::Empty);
        }

        for c in tag.chars() {
            if !c.is_ascii_alphanumeric() {
                return Err(TagError::IllegalChar(c));
            }
        }

        tag.make_ascii_lowercase();
        Ok(Tag(tag))
    }
}

impl AsRef<str> for Tag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

/// The [certification authority authorization] resource record type.
///
/// [certification authority authorization]: https://tools.ietf.org/html/rfc8659#section-4
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CAA {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub flags: u8,
    pub tag: Tag,
    pub value: Vec<u8>,
}

impl_to_type!(CAA);

impl Display for CAA {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} CAA {} {} {}",
            self.domain_name,
            self.ttl,
            self.class,
            self.flags,
            self.tag,
            encode(&self.value)
        )
    }
}
