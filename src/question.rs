//! This module contains struct for [questions] handling.
//!
//! The [`Question`] struct represents an arbitrary question. Each [type] has a dedicated enum
//! variant in the [`QType`] enum.
//!
//! The [`QClass`] enum represents the [class] field of the resource record.
//!
//! The [`QType`] enum represents the [type] field of the resource record.
//!
//! # Example
//! ```rust
//! use dns_message_parser::question::{Question, QType, QClass};
//! use std::convert::TryInto;
//!
//! // Init A record
//! let question = Question {
//!     // The domain name of the question
//!     domain_name: "example.org".try_into().unwrap(),
//!     // The class of the question
//!     q_class: QClass::IN,
//!     // The type of the question
//!     q_type: QType::A,
//! };
//!
//! // Encode the A question into bytes::BytesMut
//! let bytes = question.encode().unwrap();
//!
//! // Decode the A question into a Question struct
//! let rr = Question::decode(bytes.freeze()).unwrap();
//! ```
//!
//! [`Question`]: crate::question::Question
//! [`QClass`]: crate::question::QClass
//! [`QType`]: crate::question::QType
//! [questions]: https://tools.ietf.org/html/rfc1035#section-4.1.2
//! [class]: https://tools.ietf.org/html/rfc1035#section-3.2.5
//! [type]: https://tools.ietf.org/html/rfc1035#section-3.2.3

use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

try_from_enum_to_integer! {
    #[repr(u16)]
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum QType {
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
        // OPT = 41,
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
        /// Service Binding
        SVCB = 64,
        /// Service Binding specific to the https and http schemes
        HTTPS = 65,

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
        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        ALL = 255,
    }
}

try_from_enum_to_integer! {
    #[repr(u16)]
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum QClass {
        IN = 1,
        CS = 2,
        CH = 3,
        HS = 4,
        ANY = 255,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    pub domain_name: DomainName,
    pub q_class: QClass,
    pub q_type: QType,
}

impl Display for Question {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} {} {}", self.domain_name, self.q_class, self.q_type)
    }
}
