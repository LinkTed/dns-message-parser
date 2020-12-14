#![allow(non_camel_case_types)]

mod decode;
mod dns;
mod domain_name;
mod encode;
#[macro_use]
mod macros;
mod question;
pub mod rr;
mod subtypes;

pub use decode::{DecodeError, DecodeResult};
pub use dns::{Dns, Flags};
pub use domain_name::{DomainName, DomainNameError};
pub use encode::{EncodeError, EncodeResult};
pub use question::{QClass, QType, Question};
pub use subtypes::{Opcode, RCode};

pub const MAXIMUM_DNS_PACKET_SIZE: usize = 65536;
