use super::Class;
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// The [X.400 pointer] resource record type.
///
/// [X.400 pointer]: https://tools.ietf.org/html/rfc2163#section-4
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PX {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub preference: u16,
    pub map822: DomainName,
    pub mapx400: DomainName,
}

impl_to_type!(PX);

impl Display for PX {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} PX {} {} {}",
            self.domain_name, self.ttl, self.class, self.preference, self.map822, self.mapx400,
        )
    }
}
