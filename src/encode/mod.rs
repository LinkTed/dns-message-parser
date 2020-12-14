#[macro_use]
mod macros;
mod dns;
mod domain_name;
mod encoder;
mod error;
mod helpers;
mod question;
mod rr;
#[cfg(test)]
mod tests;

use encoder::Encoder;
pub use error::EncodeError;

pub type EncodeResult<T> = std::result::Result<T, EncodeError>;
