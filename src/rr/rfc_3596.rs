use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::Ipv6Addr;

/// The [IPv6] [host address] resource record type.
///
/// [IPv6]: https://tools.ietf.org/html/rfc2460
/// [host address]: https://tools.ietf.org/html/rfc3596#section-2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AAAA {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub ipv6_addr: Ipv6Addr,
}

impl_to_type!(AAAA);

impl Display for AAAA {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} IN AAAA {}",
            self.domain_name, self.ttl, self.ipv6_addr,
        )
    }
}
