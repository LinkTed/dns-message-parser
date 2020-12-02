pub use super::{
    A, AAAA, AFSDB, CNAME, DNAME, EID, GPOS, HINFO, ISDN, KX, LOC, MB, MD, MF, MG, MINFO, MR, MX,
    NIMLOC, NS, NSAP, NULL, OPT, PTR, PX, RP, RT, SOA, SRV, SSHFP, TXT, URI, WKS, X25,
};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// RFC 1035
#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Hash)]
pub enum Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl Display for Class {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Class::IN => write!(f, "IN"),
            Class::CS => write!(f, "CS"),
            Class::CH => write!(f, "CH"),
            Class::HS => write!(f, "HS"),
        }
    }
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

pub trait ToType {
    fn to_type(&self) -> Type;
}

#[derive(Debug, PartialEq, Clone)]
pub enum RR {
    A(A),
    NS(NS),
    MD(MD),
    MF(MF),
    CNAME(CNAME),
    SOA(SOA),
    MB(MB),
    MG(MG),
    MR(MR),
    NULL(NULL),
    WKS(WKS),
    PTR(PTR),
    HINFO(HINFO),
    MINFO(MINFO),
    MX(MX),
    TXT(TXT),
    RP(RP),
    AFSDB(AFSDB),
    X25(X25),
    ISDN(ISDN),
    RT(RT),
    NSAP(NSAP),
    PX(PX),
    GPOS(GPOS),
    AAAA(AAAA),
    LOC(LOC),
    NIMLOC(NIMLOC),
    SRV(SRV),
    KX(KX),
    DNAME(DNAME),
    OPT(OPT),
    SSHFP(SSHFP),
    URI(URI),
    EID(EID),
}

impl Display for RR {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            RR::A(a) => a.fmt(f),
            RR::NS(ns) => ns.fmt(f),
            RR::MD(md) => md.fmt(f),
            RR::MF(mf) => mf.fmt(f),
            RR::CNAME(c_name) => c_name.fmt(f),
            RR::SOA(soa) => soa.fmt(f),
            RR::MB(mb) => mb.fmt(f),
            RR::MG(mg) => mg.fmt(f),
            RR::MR(mr) => mr.fmt(f),
            RR::NULL(null) => null.fmt(f),
            RR::WKS(wks) => wks.fmt(f),
            RR::PTR(ptr) => ptr.fmt(f),
            RR::HINFO(h_info) => h_info.fmt(f),
            RR::MINFO(m_info) => m_info.fmt(f),
            RR::MX(mx) => mx.fmt(f),
            RR::TXT(txt) => txt.fmt(f),
            RR::RP(rp) => rp.fmt(f),
            RR::AFSDB(afsdb) => afsdb.fmt(f),
            RR::X25(x_25) => x_25.fmt(f),
            RR::ISDN(isdn) => isdn.fmt(f),
            RR::RT(rt) => rt.fmt(f),
            RR::NSAP(nsap) => nsap.fmt(f),
            RR::PX(px) => px.fmt(f),
            RR::GPOS(gpos) => gpos.fmt(f),
            RR::AAAA(aaaa) => aaaa.fmt(f),
            RR::LOC(loc) => loc.fmt(f),
            RR::NIMLOC(nim_loc) => nim_loc.fmt(f),
            RR::SRV(srv) => srv.fmt(f),
            RR::KX(kx) => kx.fmt(f),
            RR::DNAME(d_name) => d_name.fmt(f),
            RR::OPT(opt) => opt.fmt(f),
            RR::SSHFP(ssh_fp) => ssh_fp.fmt(f),
            RR::URI(uri) => uri.fmt(f),
            RR::EID(eid) => eid.fmt(f),
        }
    }
}
