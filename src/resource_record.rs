use crate::{
    AFSDBSubtype, Class, DomainName, QClass, QType, Question, SSHFPAlgorithm, SSHFPType, Type,
};

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
    OPT, // TODO
    // TODO APL
    // TODO DS
    SSHFP(SSHFPAlgorithm, SSHFPType, Vec<u8>),
    // TODO IPSECKEY
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

#[derive(Debug, Getters, PartialEq)]
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
