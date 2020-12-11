use crate::rr::{
    AFSDBSubtype, AddressNumber, Class, EDNSOptionCode, SSHFPAlgorithm, SSHFPType, Type,
};
use crate::{Opcode, QClass, QType, RCode};
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum EncodeError {
    #[error("String too big to be encoded as u8: {0}")]
    String(usize),
    #[error("Length too big to be encoded as u16: {0}")]
    Length(usize),
    #[error("Not enough bytes to set the data at the index: got {0} index {1}")]
    NotEnoughBytes(usize, usize),
    #[error("Could not convert to u16: {0}")]
    QType(QType),
    #[error("Could not convert to u16: {0}")]
    QClass(QClass),
    #[error("Could not convert to u16: {0}")]
    Type(Type),
    #[error("Could not convert to u16: {0}")]
    Class(Class),
    #[error("Could not convert to u8: {0}")]
    Opcode(Opcode),
    #[error("Could not convert to u8: {0}")]
    RCode(RCode),
    #[error("Could not compressed domain name, because offset is too large: {0}")]
    Compression(u16),
    #[error("Could not compressed domain name, because many recursions: {0}")]
    MaxRecursion(usize),
    #[error("Could not convert AFSDBSubtype to u16: {0}")]
    AFSDBSubtype(AFSDBSubtype),
    #[error("Could not convert SSHFPAlgorithm to u8: {0}")]
    SSHFPAlgorithm(SSHFPAlgorithm),
    #[error("Could not convert SSHFPType to u8: {0}")]
    SSHFPType(SSHFPType),
    #[error("Could not convert EDNSOptionCode to u16: {0}")]
    EDNSOptionCode(EDNSOptionCode),
    #[error("Could not convert AddressNumber to u16: {0}")]
    ECSAddressNumber(AddressNumber),
    #[error("Could not encode the cookie server, because the lengh is not between 8 and 32: {0}")]
    CookieServerLength(usize),
}
