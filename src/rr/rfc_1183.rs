use crate::rr::Class;
use crate::DomainName;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::ops::Deref;
use thiserror::Error;

struct_domain_name_domain_name!(
    /// The [responsible person] resource record type.
    ///
    /// [responsible person]: https://tools.ietf.org/html/rfc1183#section-2
    RP,
    mbox_dname,
    txt_dname
);

try_from_enum_to_integer_without_display! {
    #[repr(u16)]
    #[derive(Debug, Clone, Eq, Hash, PartialEq)]
    pub enum AFSDBSubtype {
        VolumeLocationServer = 1,
        DCEAuthenticationServer = 2,
    }
}

impl Display for AFSDBSubtype {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            AFSDBSubtype::VolumeLocationServer => write!(f, "1"),
            AFSDBSubtype::DCEAuthenticationServer => write!(f, "2"),
        }
    }
}

/// The [AFS Data base location] resource record type:
///
/// [AFS Data base location]: https://tools.ietf.org/html/rfc1183#section-1
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AFSDB {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub subtype: AFSDBSubtype,
    pub hostname: DomainName,
}

impl_to_type!(AFSDB);

impl Display for AFSDB {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} AFSDB {} {}",
            self.domain_name, self.ttl, self.class, self.subtype, self.hostname
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum PSDNAddressError {
    #[error("PSDN address contains illegal character: {0}")]
    IllegalChar(char),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PSDNAddress(String);

impl TryFrom<String> for PSDNAddress {
    type Error = PSDNAddressError;

    fn try_from(psdn_address: String) -> Result<Self, Self::Error> {
        for c in psdn_address.chars() {
            if !c.is_ascii_digit() {
                return Err(PSDNAddressError::IllegalChar(c));
            }
        }
        Ok(PSDNAddress(psdn_address))
    }
}

impl Deref for PSDNAddress {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for PSDNAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0,)
    }
}

/// The [X25] resource record type.
///
/// [X25]: https://tools.ietf.org/html/rfc1183#section-3.1
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct X25 {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub psdn_address: PSDNAddress,
}

impl_to_type!(X25);

impl Display for X25 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} X25 {}",
            self.domain_name, self.ttl, self.class, self.psdn_address,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum ISDNError {
    #[error("Address contains illegal character: {0}")]
    IllegalChar(char),
    #[error("SA contains illegal character: {0}")]
    IllegalCharSA(char),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ISDNAddress(String);

impl TryFrom<String> for ISDNAddress {
    type Error = ISDNError;

    fn try_from(isdn_address: String) -> Result<Self, Self::Error> {
        for c in isdn_address.chars() {
            if !c.is_ascii_digit() {
                return Err(ISDNError::IllegalChar(c));
            }
        }
        Ok(ISDNAddress(isdn_address))
    }
}

impl Deref for ISDNAddress {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for ISDNAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0,)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SA(String);

impl TryFrom<String> for SA {
    type Error = ISDNError;

    fn try_from(sa: String) -> Result<Self, Self::Error> {
        for c in sa.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(ISDNError::IllegalCharSA(c));
            }
        }
        Ok(SA(sa))
    }
}

impl Deref for SA {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The [ISDN] resource record type.
///
/// [ISDN]: https://tools.ietf.org/html/rfc1183#section-3.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ISDN {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub isdn_address: ISDNAddress,
    pub sa: Option<SA>,
}

impl_to_type!(ISDN);

impl Display for ISDN {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} ISDN {}",
            self.domain_name, self.ttl, self.class, self.isdn_address,
        )?;
        if let Some(sa) = &self.sa {
            write!(f, " {}", sa.0)?;
        }
        Ok(())
    }
}

struct_u16_domain_name!(
    /// The [route through] resource record type.
    ///
    /// [route through]: https://tools.ietf.org/html/rfc1183#section-3.3
    RT,
    preference,
    intermediate_host
);
