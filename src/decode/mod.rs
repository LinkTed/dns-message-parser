#[macro_use]
mod macros;
mod decoder;
mod dns;
mod domain_name;
mod error;
mod helpers;
mod question;
mod rr;
#[cfg(test)]
mod tests;

use decoder::Decoder;
pub use error::DecodeError;

pub type DecodeResult<T> = std::result::Result<T, DecodeError>;
