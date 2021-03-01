//! This module contains struct for [resource records] handling.
//!
//! The [`RR`] enum represents an arbitrary resource record. Each [type] has a dedicated struct,
//! which has a variant in the [`RR`] enum. For example, the [`A`] struct represent an A record.
//!
//! The [`Class`] enum represents the [class] field of the resource record.
//!
//! The [`Type`] enum represents the [type] field of the resource record.
//!
//! *Yet there are some missing resource records and types*
//!
//! # Example
//! ```rust
//! use dns_message_parser::rr::{RR, A};
//! use std::convert::TryInto;
//!
//! // Init A record
//! let a = A {
//!     // The domain name of the A record
//!     domain_name: "example.org".try_into().unwrap(),
//!     // The time to live of the A record
//!     ttl: 1000,
//!     // The address of the A record
//!     ipv4_addr: "10.0.0.1".parse().unwrap(),
//! };
//!
//! // Convert the resource record into a RR
//! let rr = RR::A(a);
//!
//! // Encode the A record into bytes::BytesMut
//! let bytes = rr.encode().unwrap();
//!
//! // Decode the A record into a RR enum
//! let rr = RR::decode(bytes.freeze()).unwrap();
//! ```
//!
//! [`A`]: crate::rr::A
//! [`RR`]: crate::rr::RR
//! [`Class`]: crate::rr::Class
//! [`Type`]: crate::rr::Type
//! [resource records]: https://tools.ietf.org/html/rfc1035#section-4.1.3
//! [class]: https://tools.ietf.org/html/rfc1035#section-3.2.4
//! [type]: https://tools.ietf.org/html/rfc1035#section-3.2.2

#[macro_use]
mod macros;
pub mod edns;
mod enums;
mod rfc_1035;
mod rfc_1183;
mod rfc_1706;
mod rfc_1712;
mod rfc_1876;
mod rfc_2163;
mod rfc_2230;
mod rfc_2782;
mod rfc_3123;
mod rfc_3596;
mod rfc_3658;
mod rfc_4034;
mod rfc_6672;
mod rfc_6742;
mod rfc_7043;
mod rfc_7553;
mod subtypes;
mod unknown;

pub use edns::rfc_6891::OPT;
pub use enums::{Class, ToType, Type, RR};
pub use rfc_1035::{A, CNAME, HINFO, MB, MD, MF, MG, MINFO, MR, MX, NS, NULL, PTR, SOA, TXT, WKS};
pub use rfc_1183::{
    AFSDBSubtype, ISDNAddress, ISDNError, PSDNAddress, X25Error, AFSDB, ISDN, RP, RT, SA, X25,
};
pub use rfc_1706::NSAP;
pub use rfc_1712::GPOS;
pub use rfc_1876::LOC;
pub use rfc_2163::PX;
pub use rfc_2230::KX;
pub use rfc_2782::SRV;
pub use rfc_3123::{APItem, APL, APL_NEGATION_MASK};
pub use rfc_3596::AAAA;
pub use rfc_3658::{SSHFPAlgorithm, SSHFPType, SSHFP};
pub use rfc_4034::{
    AlgorithmType, DigestType, DNSKEY, DNSKEY_ZERO_MASK, DS, SECURE_ENTRY_POINT_FLAG, ZONE_KEY_FLAG,
};
pub use rfc_6672::DNAME;
pub use rfc_6742::{L32, L64, LP, NID};
pub use rfc_7043::{EUI48, EUI64};
pub use rfc_7553::URI;
pub use subtypes::{Address, AddressError, AddressFamilyNumber};
pub use unknown::{EID, NIMLOC};
