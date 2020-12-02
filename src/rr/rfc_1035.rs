use super::Class;
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::Ipv4Addr;

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

struct_domain_name!(NS, ns_d_name);

struct_domain_name!(MD, mad_name);

struct_domain_name!(MF, mad_name);

struct_domain_name!(CNAME, c_name);

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

struct_domain_name!(MB, mad_name);

struct_domain_name!(MG, mgm_name);

struct_domain_name!(MR, new_name);

struct_vec!(NULL, data);

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

struct_domain_name!(PTR, ptr_d_name);

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

struct_domain_name_domain_name!(MINFO, r_mail_bx, e_mail_bx);

struct_u16_domain_name!(MX, preference, exchange);

struct_string!(TXT, string);
