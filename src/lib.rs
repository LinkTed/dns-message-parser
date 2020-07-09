#[macro_use(FromPrimitive, ToPrimitive)]
extern crate num_derive;
#[macro_use(lazy_static)]
extern crate lazy_static;
#[macro_use(Getters, Setters)]
extern crate getset;

mod decode;
pub use decode::DecodeError;

mod dns;
pub use dns::{Dns, Flags};

mod domain_name;
pub use domain_name::{DomainError, DomainName};

mod encode;
pub use encode::EncodeError;

mod resource_record;
pub use resource_record::{RData, RR};

mod question;
pub use question::{QClass, QClass_, QType, QType_, Question};

pub const MAXIMUM_DNS_PACKET_SIZE: usize = 65536;

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,

    Notify = 4,
    Update = 5,
    DSO = 6,
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq)]
pub enum RCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    DSOTYPENI = 11,

    BADVERS = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22,
    BADCOOKIE = 23,
}

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Hash)]
pub enum Type {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    #[allow(non_camel_case_types)]
    NSAP_PTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    EID = 31,
    NIMLOC = 32,
    SRV = 33,
    ATMA = 34,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38,
    DNAME = 39,
    SINK = 40,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,

    HIP = 55,
    NINFO = 56,
    RKEY = 57,
    TALINK = 58,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,

    SPF = 99,
    UINFO = 100,
    UID = 101,
    GID = 102,
    UNSPEC = 103,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,
    EUI48 = 108,
    EUI64 = 109,

    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    // TODO QType?
    URI = 256,
    CAA = 257,
    AVC = 258,
    DOA = 259,
    AMTRELAY = 260,

    TA = 32768,
    DLV = 32769,
}

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Hash)]
pub enum Class {
    IN = 1,

    CH = 3,
    HS = 4,

    NONE = 254,
}

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq)]
pub enum AFSDBSubtype {
    VolumeLocationServer = 1,
    DCEAuthenticationServer = 2,
}

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq)]
pub enum SSHFPAlgorithm {
    Reserved = 0,
    RSA = 1,
    DSS = 2,
}

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq)]
pub enum SSHFPType {
    Reserved = 0,
    Sha1 = 1,
}

//NSAP = 22,
//NSAP_PTR = 23,
//SIG = 24,
//KEY = 25,
//PX = 26,
//GPOS = 27,

//NXT = 30,
//EID = 31,
//NIMLOC = 32,
//SRV = 33,
//ATMA = 34,
//NAPTR = 35,
//KX = 36,
//CERT = 37,
//A6 = 38,
//DNAME = 39,
//SINK = 40,
//OPT = 41,
//APL = 42,
//DS = 43,
//SSHFP = 44,
//IPSECKEY = 45,
//RRSIG = 46,
//NSEC = 47,
//DNSKEY = 48,
//DHCID = 49,
//NSEC3 = 50,
//NSEC3PARAM = 51,
//TLSA = 52,
//SMIMEA = 53,
//HIP = 55,
//NINFO = 56,
//RKEY = 57,
//TALINK = 58,
//CDS = 59,
//CDNSKEY = 60,
//OPENPGPKEY = 61,
//CSYNC = 62,
//ZONEMD = 63,
//SPF = 99,
//UINFO = 100,
//UID = 101,
//GID = 102,
//UNSPEC = 103,
//NID = 104,
//L32 = 105,
//L64 = 106,
//LP = 107,
//EUI48 = 108,
//EUI64 = 109,
//TKEY = 249,
//TSIG = 250,
//IXFR = 251,
//AXFR = 252,
//MAILB = 253,
//MAILA = 254,
//ALL = 255,
//URI = 256,
//CAA = 257,
//AVC = 258,
//DOA = 259,
//AMTRELAY = 260,
//TA = 32768,
//DLV = 32769
