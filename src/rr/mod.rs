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
