use super::Class;
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// The [location information] resource record type.
///
/// [location information]: https://tools.ietf.org/html/rfc1876#section-2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LOC {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub version: u8,
    pub size: u8,
    pub horiz_pre: u8,
    pub vert_pre: u8,
    pub latitube: u32,
    pub longitube: u32,
    pub altitube: u32,
}

impl_to_type!(LOC);

impl Display for LOC {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} LOC {} {} {} {} {} {} {}",
            self.domain_name,
            self.ttl,
            self.class,
            self.version,
            self.size,
            self.horiz_pre,
            self.vert_pre,
            self.latitube,
            self.longitube,
            self.altitube,
        )
    }
}
