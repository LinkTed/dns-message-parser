use super::{Cookie, Padding, ECS};
use std::fmt::{Display, Formatter, Result as FmtResult};

try_from_enum_to_integer! {
    #[repr(u16)]
    #[derive(Debug, Clone, PartialEq)]
    pub enum EDNSOptionCode {
        ECS = 0x00008,
        Cookie = 0x000a,
        Padding = 0x000c,
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum EDNSOption {
    ECS(ECS),
    Cookie(Cookie),
    Padding(Padding),
}

impl Display for EDNSOption {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            EDNSOption::ECS(ecs) => ecs.fmt(f),
            EDNSOption::Cookie(cookie) => cookie.fmt(f),
            EDNSOption::Padding(padding) => padding.fmt(f),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct OPT {
    pub requestor_payload_size: u16,
    pub extend_rcode: u8,
    pub version: u8,
    pub dnssec: bool,
    pub edns_options: Vec<EDNSOption>,
}

impl_to_type!(OPT);

impl Display for OPT {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // TODO extend_rcode
        write!(
            f,
            ". 0 IN OPT {} {} {} {}",
            self.requestor_payload_size, self.extend_rcode, self.version, self.dnssec,
        )?;
        for edns_option in &self.edns_options {
            write!(f, " {}", edns_option)?;
        }
        Ok(())
    }
}
