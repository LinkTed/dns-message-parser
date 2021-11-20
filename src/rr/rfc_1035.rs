use super::{Class, NonEmptyVec};
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::Ipv4Addr;

/// The [IPv4] [host address] resource record type.
///
/// [IPv4]: https://tools.ietf.org/html/rfc791
/// [host address]: https://tools.ietf.org/html/rfc1035#section-3.4.1
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct A {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub ipv4_addr: Ipv4Addr,
}

impl_to_type!(A);

impl Display for A {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} IN A {}",
            self.domain_name, self.ttl, self.ipv4_addr
        )
    }
}

struct_domain_name!(
    /// The [authoritative name server] resource record type.
    ///
    /// [authoritative name server]: https://tools.ietf.org/html/rfc1035#section-3.3.11
    NS,
    ns_d_name
);

struct_domain_name!(
    /// The [mail destination] resource record type. (obsolete)
    ///
    /// [mail destination]: https://tools.ietf.org/html/rfc1035#section-3.3.4
    MD,
    mad_name
);

struct_domain_name!(
    /// The [mail forwarder] resource record type. (obsolete)
    ///
    /// [mail forwarder]: https://tools.ietf.org/html/rfc1035#section-3.3.5
    MF,
    mad_name
);

struct_domain_name!(
    /// The [canonical name] resource record type.
    ///
    /// [canonical name]: https://tools.ietf.org/html/rfc1035#section-3.3.1
    CNAME,
    c_name
);

/// The [start of a zone of authority] resource record type.
///
/// [start of a zone of authority]: https://tools.ietf.org/html/rfc1035#section-3.3.13
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SOA {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub m_name: DomainName,
    pub r_name: DomainName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub min_ttl: u32,
}

impl_to_type!(SOA);

impl Display for SOA {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} SOA {} {} ({} {} {} {} {})",
            self.domain_name,
            self.ttl,
            self.class,
            self.m_name,
            self.r_name,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.min_ttl,
        )
    }
}

struct_domain_name!(
    /// The [mailbox domain name] resource record type.
    ///
    /// [mailbox domain name]: https://tools.ietf.org/html/rfc1035#section-3.3.3
    MB,
    mad_name
);

struct_domain_name!(
    /// The [mail group member] resource record type.
    ///
    /// [mail group member]: https://tools.ietf.org/html/rfc1035#section-3.3.6
    MG,
    mgm_name
);

struct_domain_name!(
    /// The [mail rename domain name] resource record type.
    ///
    /// [mail rename domain name]: https://tools.ietf.org/html/rfc1035#section-3.3.8
    MR,
    new_name
);

struct_vec!(
    /// The [null] type.
    ///
    /// [null]: https://tools.ietf.org/html/rfc1035#section-3.3.10
    NULL,
    data
);

/// The [well known service] description resource record type.
///
/// [well known service]: https://tools.ietf.org/html/rfc1035#section-3.4.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WKS {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub ipv4_addr: Ipv4Addr,
    pub protocol: u8,
    pub bit_map: Vec<u8>,
}

impl_to_type!(WKS);

impl Display for WKS {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // TODO
        write!(
            f,
            "{} {} IN WKS {} {:x?}",
            self.domain_name, self.ttl, self.protocol, self.bit_map
        )
    }
}

struct_domain_name!(
    /// The [domain name pointer] resource record type.
    ///
    /// [domain name pointer]: https://tools.ietf.org/html/rfc1035#section-3.3.12
    PTR,
    ptr_d_name
);

/// The [host information] resource record type.
///
/// [host information]: https://tools.ietf.org/html/rfc1035#section-3.3.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HINFO {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub cpu: String,
    pub os: String,
}

impl_to_type!(HINFO);

impl Display for HINFO {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // TODO
        write!(
            f,
            "{} {} {} HINFO {} {}",
            self.domain_name, self.ttl, self.class, self.cpu, self.os,
        )
    }
}

struct_domain_name_domain_name!(
    /// The [mailbox or mail list information] resource record type.
    ///
    /// [mailbox or mail list information]: https://tools.ietf.org/html/rfc1035#section-3.3.7
    MINFO,
    r_mail_bx,
    e_mail_bx
);

struct_u16_domain_name!(
    /// The [mail exchange] resource record type.
    ///
    /// [mail exchange]: https://tools.ietf.org/html/rfc1035#section-3.3.9
    MX,
    preference,
    exchange
);

/// The [text] resource record type.
///
/// [text]: https://tools.ietf.org/html/rfc1035#section-3.3.14
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TXT {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub strings: NonEmptyVec<String>,
}

impl_to_type!(TXT);

impl Display for TXT {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} {} {} TXT", self.domain_name, self.ttl, self.class,)?;
        for string in self.strings.iter() {
            write!(f, " \"{}\"", string.escape_default())?;
        }
        Ok(())
    }
}
