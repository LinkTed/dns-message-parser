use crate::rr::{AddressError, Class, CookieError, ISDNError, Type, X25Error};
use crate::{Dns, DomainName, DomainNameError};
use hex::FromHexError;
use std::str::Utf8Error;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum DecodeError {
    #[error("Not enough bytes to decode: got {0} offset {1}")]
    NotEnoughBytes(usize, usize),
    #[error("Too many bytes to decode: got {0} parsed {1}")]
    TooManyBytes(usize, usize),
    #[error("DNS packet is too big: {0}")]
    DnsPacketTooBig(usize),
    #[error("Could not decode Opcode: {0}")]
    Opcode(u8),
    #[error("Z bit is not zero: {0}")]
    ZNotZeroes(u8),
    #[error("Could not decode RCode: {0}")]
    RCode(u8),
    #[error("Could not decode Type: {0}")]
    Type(u16),
    #[error("Could not decode Class: {0}")]
    Class(u16),
    #[error("Could not decode QType: {0}")]
    QType(u16),
    #[error("Could not decode QClass: {0}")]
    QClass(u16),
    #[error("Could not decode string as UTF-8: {0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("Could not decode domain name: {0}")]
    DomainNameError(#[from] DomainNameError),
    #[error("Decode of type {0} is not yet implemented")]
    NotYetImplemented(Type),
    #[error("Could not decode hex string: {0}")]
    FromHexError(#[from] FromHexError),
    #[error("Offset is not zero: {0}")]
    Offset(usize),
    #[error("Class is not IN for A record: {0}")]
    AClass(Class),
    #[error("Class is not IN for WKS record: {0}")]
    WKSClass(Class),
    #[error("Could not decode AFSDBSubtype: {0}")]
    AFSDBSubtype(u16),
    #[error("Could not decode X25: {0}")]
    X25Error(#[from] X25Error),
    #[error("Could not decode ISDN: {0}")]
    ISDNError(#[from] ISDNError),
    #[error("Could not decode GPOS")]
    GPOS,
    #[error("Class is not IN for AAAA record: {0}")]
    AAAAClass(Class),
    #[error("Domain name is not root: {0}")]
    OPTDomainName(DomainName),
    #[error("OPT header bits is not zero: {0}")]
    OPTZero(u8),
    #[error("Could not decode ENDSOptionCode: {0}")]
    EDNSOptionCode(u16),
    #[error("Could not decode Address: {0}")]
    AddressError(#[from] AddressError),
    #[error("Class is not IN for APL record: {0}")]
    APLClass(Class),
    #[error("Could not decode Cookie: {0}")]
    CookieError(#[from] CookieError),
    #[error("Could not decode AddressNumber: {0}")]
    EcsAddressNumber(u16),
    #[error("The IPv4 Address is too big: {0}")]
    EcsTooBigIpv4Address(usize),
    #[error("The IPv6 Address is too big: {0}")]
    EcsTooBigIpv6Address(usize),
    #[error("The cookie length is not 8 or between 16 and 40 bytes: {0}")]
    CookieLength(usize),
    #[error("Could not decode SSHFPAlgorithm: {0}")]
    SSHFPAlgorithm(u8),
    #[error("Could not decode SSHFPType: {0}")]
    SSHFPType(u8),
    #[error("Could not decode the domain name, the because maximum recursion is reached: {0}")]
    MaxRecursion(usize),
    #[error("The are remaining bytes, which was not parsed")]
    RemainingBytes(usize, Dns),
}
