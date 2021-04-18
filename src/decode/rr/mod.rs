#[macro_use]
mod macros;
mod draft_ietf_dnsop_svcb_https;
mod edns;
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
mod rfc_8659;
mod subtypes;
#[cfg(test)]
mod tests;
mod unknown;

use enums::Header;
