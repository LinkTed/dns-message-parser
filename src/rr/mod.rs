//! This module contains struct for [resource records] handling.
//!
//! The [RR] enum represents arbitrary a resource record. Each type has a dedicated struct (for
//! example the [A] record), which has a variant in the [RR] enum.
//!
//! The [Class] enum represents the [class] field of the resource record.
//!
//! The [Type] enum represents the [type] field of the resource record.
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
//! [A]: crate::rr::A
//! [RR]: crate::rr::RR
//! [Class]: crate::rr::Class
//! [Type]: crate::rr::Type
//! [resource records]: https://tools.ietf.org/html/rfc1035#section-3.2
//! [class]: https://tools.ietf.org/html/rfc1035#section-3.2.4
//! [type]: https://tools.ietf.org/html/rfc1035#section-3.2.2

#[macro_use]
mod macros;
mod enums;
mod rfc_1035;
mod rfc_1183;
mod rfc_1706;
mod rfc_1712;
mod rfc_1876;
mod rfc_2163;
mod rfc_2230;
mod rfc_2782;
mod rfc_3596;
mod rfc_3658;
mod rfc_6672;
mod rfc_6891;
mod rfc_7553;
mod rfc_7871;
mod rfc_7873;
mod unknown;

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
pub use rfc_3596::AAAA;
pub use rfc_3658::{SSHFPAlgorithm, SSHFPType, SSHFP};
pub use rfc_6672::DNAME;
pub use rfc_6891::{EDNSOption, EDNSOptionCode, OPT};
pub use rfc_7553::URI;
pub use rfc_7871::{Address, AddressNumber, ECSError, ECS};
pub use rfc_7873::Cookie;
pub use unknown::{EID, NIMLOC};
