use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::Ipv6Addr;

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
