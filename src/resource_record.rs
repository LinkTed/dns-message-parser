use crate::{
    AFSDBSubtype, Class, DomainName, QClass, QType, Question, SSHFPAlgorithm, SSHFPType, Type,
};

use hex::encode as hex_encode;

use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Clone)]
pub enum RData {
    A(Ipv4Addr),
    NS(DomainName),
    MD(DomainName),
    MF(DomainName),
    CNAME(DomainName),
    SOA(DomainName, DomainName, u32, u32, u32, u32, u32),
    MB(DomainName),
    MG(DomainName),
    MR(DomainName),
    NULL(Vec<u8>),
    WKS(Ipv4Addr, u8, Vec<u8>),
    PTR(DomainName),
    HINFO(String, String),
    MINFO(DomainName, DomainName),
    MX(u16, DomainName),
    TXT(String),
    RP(DomainName, DomainName),
    AFSDB(AFSDBSubtype, DomainName),
    X25(String),
    ISDN(String, Option<String>),
    RT(u16, DomainName),
    NSAP(Vec<u8>),
    // TODO NSAP-PTR
    // TODO SIG
    KEY(u16, u8, u8, Vec<u8>),
    PX(u16, DomainName, DomainName),
    GPOS(String, String, String),
    AAAA(Ipv6Addr),
    LOC(u8, u8, u8, u8, u32, u32, u32),
    // TODO NXT
    EID(Vec<u8>),
    NIMLOC(Vec<u8>),
    SRV(u16, u16, u16, DomainName),
    // TODO ATMA
    // TODO NAPTR
    KX(u16, DomainName),
    // TODO CERT
    // TODO A6
    DNAME(DomainName),
    // TODO SINK
    OPT(u16, u8, bool, Vec<u8>), // TODO
    // TODO APL
    // TODO DS
    SSHFP(SSHFPAlgorithm, SSHFPType, Vec<u8>),
    // TODO IPSECKEY
    // TODO
    URI(u16, u16, String),
    // TODO
}

impl RData {
    pub fn get_type(&self) -> Type {
        match self {
            RData::A(_) => Type::A,
            _ => unimplemented!(),
        }
    }
}

impl Display for RData {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            RData::A(ipv4_addr) => write!(f, "A {}", ipv4_addr),
            RData::NS(ns_d_name) => write!(f, "NS {}", ns_d_name),
            RData::CNAME(c_name) => write!(f, "CNAME {}", c_name),
            RData::SOA(m_name, r_name, serial, refresh, retry, expire, min_ttl) => write!(
                f,
                "SOA {} {} ({} {} {} {} {})",
                m_name, r_name, *serial, *refresh, *retry, *expire, *min_ttl
            ),
            RData::MB(mad_name) => write!(f, "MB {}", mad_name),
            RData::MG(mgm_name) => write!(f, "MG {}", mgm_name),
            RData::MR(new_name) => write!(f, "MR {}", new_name),
            // TODO NULL
            // TODO WKS protocol bit_map
            RData::WKS(ipv4_addr, protocol, bit_map) => {
                write!(f, "WKS {} {} ({:?})", ipv4_addr, protocol, bit_map)
            }
            RData::PTR(ptr_d_name) => write!(f, "PTR {}", ptr_d_name),
            RData::HINFO(cpu, os) => write!(f, "HINFO {:?} {:?}", cpu, os),
            RData::MINFO(r_mail_bx, e_mail_bx) => write!(f, "MINFO {} {}", r_mail_bx, e_mail_bx),
            RData::MX(preference, exchange) => write!(f, "MX {} {}", preference, exchange),
            RData::TXT(string) => write!(f, "TXT {:?}", string),
            RData::RP(mbox_dname, txt_dname) => write!(f, "RP {} {}", mbox_dname, txt_dname),
            // TODO AFSDB
            RData::X25(psdn_address) => write!(f, "X25 {}", psdn_address),
            RData::ISDN(isdn_address, sa) => {
                if let Some(sa) = sa {
                    write!(f, "ISDN {} {}", isdn_address, sa)
                } else {
                    write!(f, "ISDN {}", isdn_address)
                }
            }
            RData::RT(preference, intermediate_host) => {
                write!(f, "RT {} {}", preference, intermediate_host)
            }
            // TODO NSAP
            RData::PX(preference, map822, mapx400) => {
                write!(f, "PX {} {} {}", preference, map822, mapx400)
            }
            RData::GPOS(longitude, latitude, altitude) => {
                write!(f, "GPOS {:?} {:?} {:?}", longitude, latitude, altitude)
            }
            RData::AAAA(ipv6_addr) => write!(f, "AAAA {}", ipv6_addr),
            // TODO
            RData::EID(data) => write!(f, "EID {}", hex_encode(data)),
            RData::NIMLOC(data) => write!(f, "NIMLOC {}", hex_encode(data)),
            RData::SRV(priority, weight, port, target) => {
                write!(f, "SRV {} {} {} {}", priority, weight, port, target)
            }
            RData::KX(preference, exchanger) => write!(f, "KX {} {}", preference, exchanger),
            RData::DNAME(target) => write!(f, "DNAME {}", target),
            // TODO SSHFP
            RData::URI(priority, weight, uri) => write!(f, "URI {} {} {}", priority, weight, uri),
            r_data => Debug::fmt(r_data, f),
        }
    }
}

#[derive(Debug, Clone, Getters, PartialEq)]
pub struct RR {
    #[get = "pub with_prefix"]
    pub(crate) domain_name: DomainName,
    #[get = "pub with_prefix"]
    pub(crate) class: Class,
    #[get = "pub with_prefix"]
    pub(crate) ttl: u32,
    #[get = "pub with_prefix"]
    pub(crate) rdata: RData,
}

impl RR {
    pub fn new(domain_name: DomainName, class: Class, ttl: u32, rdata: RData) -> RR {
        RR {
            domain_name,
            class,
            ttl,
            rdata,
        }
    }

    pub fn split(self) -> (Question, u32, RData) {
        let qclass = QClass::Class(self.class);
        let qtype = QType::Type(self.rdata.get_type());
        let question = Question::new(self.domain_name, qclass, qtype);
        (question, self.ttl, self.rdata)
    }
}

impl Display for RR {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {:?} {}",
            self.domain_name, self.ttl, self.class, self.rdata
        )
    }
}
