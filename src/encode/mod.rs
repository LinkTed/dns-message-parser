#[macro_use]
mod encoder;
mod dns;
mod domain_name;
mod error;
mod helpers;
mod question;
mod rr;
#[cfg(test)]
mod tests;

use encoder::Encoder;
pub use error::EncodeError;

pub type EncodeResult<T> = std::result::Result<T, EncodeError>;
