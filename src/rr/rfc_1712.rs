use super::Class;
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GPOS {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub longitude: String,
    pub latitude: String,
    pub altitude: String,
}

impl_to_type!(GPOS);

impl Display for GPOS {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} GPOS {} {} {}",
            self.domain_name, self.ttl, self.class, self.longitude, self.latitude, self.altitude,
        )
    }
}
