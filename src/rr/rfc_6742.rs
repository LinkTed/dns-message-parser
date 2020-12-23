use std::fmt::{Display, Formatter, Result as FmtResult};

struct_u16_u64!(NID, preference, node_id);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct L32 {
    pub domain_name: crate::DomainName,
    pub ttl: u32,
    pub class: super::Class,
    pub preference: u16,
    pub locator_32: u32,
}

impl_to_type!(L32);

impl Display for L32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let bytes = self.locator_32.to_be_bytes();
        write!(
            f,
            "{} {} {} L32 {} {}.{}.{}.{}",
            self.domain_name,
            self.ttl,
            self.class,
            self.preference,
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
        )
    }
}

struct_u16_u64!(L64, preference, locator_64);

struct_u16_domain_name!(LP, preference, fqdn);
