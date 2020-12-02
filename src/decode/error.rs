use crate::rr::{Class, ECSError, ISDNError, X25Error};
use crate::{DomainName, DomainNameError};
use hex::FromHexError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    NotEnoughData,
    TooMuchData,
    OpcodeError,
    ZNotZeroes,
    RCodeError,
    TypeError(u16),
    ClassError(u16),
    QTypeError(u16),
    QClassError(u16),
    Utf8Error(Utf8Error),
    FromUtf8Error(FromUtf8Error),
    Domain(DomainNameError),
    NotYetImplemented,
    FromHexError(FromHexError),
    OffsetError(usize),

    AError(Class),
    WKSError(Class),
    AFSDBSubtypeError(u16),
    X25Error(X25Error),
    ISDNError(ISDNError),
    GPOSError,
    AAAAError(Class),
    OPTDomainNameError(DomainName),
    OPTZeroError(u8),
    EDNSOptionCodeError(u16),
    ECSError(ECSError),
    EcsAddressNumberError(u16),
    EcsTooBigIpv4Address(usize),
    EcsTooBigIpv6Address(usize),
    CookieLengthError(usize),
    SSHFPAlgorithmError(u8),
    SSHFPTypeError(u8),
    MaxRecursionError(usize),
    RemainingBytes(usize),
}

impl From<FromUtf8Error> for DecodeError {
    fn from(from_utf8_error: FromUtf8Error) -> Self {
        DecodeError::FromUtf8Error(from_utf8_error)
    }
}

impl From<Utf8Error> for DecodeError {
    fn from(utf8_error: Utf8Error) -> Self {
        DecodeError::Utf8Error(utf8_error)
    }
}

impl From<DomainNameError> for DecodeError {
    fn from(domain_name_error: DomainNameError) -> Self {
        DecodeError::Domain(domain_name_error)
    }
}

impl From<FromHexError> for DecodeError {
    fn from(from_hex_error: FromHexError) -> Self {
        DecodeError::FromHexError(from_hex_error)
    }
}

impl From<ECSError> for DecodeError {
    fn from(ecs_error: ECSError) -> Self {
        DecodeError::ECSError(ecs_error)
    }
}

impl From<X25Error> for DecodeError {
    fn from(x25_error: X25Error) -> Self {
        DecodeError::X25Error(x25_error)
    }
}

impl From<ISDNError> for DecodeError {
    fn from(isdn_error: ISDNError) -> Self {
        DecodeError::ISDNError(isdn_error)
    }
}
