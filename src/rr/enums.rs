pub use super::{
    A, AAAA, AFSDB, CNAME, DNAME, EID, EUI48, EUI64, GPOS, HINFO, ISDN, KX, LOC, MB, MD, MF, MG,
    MINFO, MR, MX, NIMLOC, NS, NSAP, NULL, OPT, PTR, PX, RP, RT, SOA, SRV, SSHFP, TXT, URI, WKS,
    X25,
};
use std::fmt::{Display, Formatter, Result as FmtResult};

try_from_enum_to_integer! {
    #[repr(u16)]
    /// The [class] field in the [resource records].
    ///
    /// [class]: https://tools.ietf.org/html/rfc1035#section-3.2.4
    /// [resource records]: crate::rr::RR
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum Class {
        /// The Internet class.
        IN = 1,
        /// The CSNET class. (obsolete)
        CS = 2,
        /// The CHAOS class.
        CH = 3,
        /// The Hesiod class.
        HS = 4,
    }
}

try_from_enum_to_integer! {
    #[repr(u16)]
    /// The [type] field in the [resource records].
    ///
    /// [type]: https://tools.ietf.org/html/rfc1035#section-3.2.2
    /// [resource records]: crate::rr::RR
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum Type {
        /// The [IPv4] [host address] type.
        ///
        /// [IPv4]: https://tools.ietf.org/html/rfc791
        /// [host address]: https://tools.ietf.org/html/rfc1035#section-3.4.1
        A = 1,
        /// The [authoritative name server] type.
        ///
        /// [authoritative name server]: https://tools.ietf.org/html/rfc1035#section-3.3.11
        NS = 2,
        /// The [mail destination] type. (obsolete)
        ///
        /// [mail destination]: https://tools.ietf.org/html/rfc1035#section-3.3.4
        MD = 3,
        /// The [mail forwarder] type. (obsolete)
        ///
        /// [mail forwarder]: https://tools.ietf.org/html/rfc1035#section-3.3.5
        MF = 4,
        /// The [canonical name] type.
        ///
        /// [canonical name]: https://tools.ietf.org/html/rfc1035#section-3.3.1
        CNAME = 5,
        /// The [start of a zone of authority] type.
        ///
        /// [start of a zone of authority]: https://tools.ietf.org/html/rfc1035#section-3.3.13
        SOA = 6,
        /// The [mailbox domain name] type.
        ///
        /// [mailbox domain name]: https://tools.ietf.org/html/rfc1035#section-3.3.3
        MB = 7,
        /// The [mail group member] type.
        ///
        /// [mail group member]: https://tools.ietf.org/html/rfc1035#section-3.3.6
        MG = 8,
        /// The [mail rename domain name] type.
        ///
        /// [mail rename domain name]: https://tools.ietf.org/html/rfc1035#section-3.3.8
        MR = 9,
        /// The [null] type.
        ///
        /// [null]: https://tools.ietf.org/html/rfc1035#section-3.3.10
        NULL = 10,
        /// The [well known service] description type.
        ///
        /// [well known service]: https://tools.ietf.org/html/rfc1035#section-3.4.2
        WKS = 11,
        /// The [domain name pointer] type.
        ///
        /// [domain name pointer]: https://tools.ietf.org/html/rfc1035#section-3.3.12
        PTR = 12,
        /// The [host information] type.
        ///
        /// [host information]: https://tools.ietf.org/html/rfc1035#section-3.3.2
        HINFO = 13,
        /// The [mailbox or mail list information] type.
        ///
        /// [mailbox or mail list information]: https://tools.ietf.org/html/rfc1035#section-3.3.7
        MINFO = 14,
        /// The [mail exchange] type.
        ///
        /// [mail exchange]: https://tools.ietf.org/html/rfc1035#section-3.3.9
        MX = 15,
        /// The [text] type.
        ///
        /// [text]: https://tools.ietf.org/html/rfc1035#section-3.3.14
        TXT = 16,
        /// The [responsible person] type.
        ///
        /// [responsible person]: https://tools.ietf.org/html/rfc1183#section-2
        RP = 17,
        /// The [AFS Data base location] type:
        ///
        /// [AFS Data base location]: https://tools.ietf.org/html/rfc1183#section-1
        AFSDB = 18,
        /// The [X25] type.
        ///
        /// [X25]: https://tools.ietf.org/html/rfc1183#section-3.1
        X25 = 19,
        /// The [ISDN] type.
        ///
        /// [ISDN]: https://tools.ietf.org/html/rfc1183#section-3.2
        ISDN = 20,
        /// The [route through] type.
        ///
        /// [route through]: https://tools.ietf.org/html/rfc1183#section-3.3
        RT = 21,
        /// The [NSAP] type.
        ///
        /// [NSAP]: https://tools.ietf.org/html/rfc1706#section-5
        NSAP = 22,
        /// The [NSAP pointer] type.
        ///
        /// [NSAP pointer]: https://tools.ietf.org/html/rfc1706#section-6
        #[allow(non_camel_case_types)]
        NSAP_PTR = 23,
        SIG = 24,
        KEY = 25,
        /// The [X.400 pointer] type.
        ///
        /// [X.400 pointer]: https://tools.ietf.org/html/rfc2163#section-4
        PX = 26,
        /// The [geographical location] type.
        ///
        /// [geographical location]: https://tools.ietf.org/html/rfc1712#section-4
        GPOS = 27,
        /// The [IPv6] [host address] type.
        ///
        /// [IPv6]: https://tools.ietf.org/html/rfc2460
        /// [host address]: https://tools.ietf.org/html/rfc3596#section-2
        AAAA = 28,
        /// The [location information] type.
        ///
        /// [location information]: https://tools.ietf.org/html/rfc1876#section-2
        LOC = 29,
        NXT = 30,
        EID = 31,
        NIMLOC = 32,
        /// The [location of services] type.
        ///
        /// [location of services]: https://tools.ietf.org/html/rfc2782
        SRV = 33,
        ATMA = 34,
        NAPTR = 35,
        /// The [key exchange] type.
        ///
        /// [key exchange]: https://tools.ietf.org/html/rfc2230#section-3
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
    EUI48(EUI48),
    EUI64(EUI64),
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
            RR::EUI48(eui_48) => eui_48.fmt(f),
            RR::EUI64(eui_64) => eui_64.fmt(f),
            RR::URI(uri) => uri.fmt(f),
            RR::EID(eid) => eid.fmt(f),
        }
    }
}
