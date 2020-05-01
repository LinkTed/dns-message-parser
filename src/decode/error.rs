use crate::DomainError;

use std::str::Utf8Error;

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    NotEnoughData,
    TooMuchData,
    OpcodeError,
    ZNotZeroes,
    RCodeError,
    TypeError,
    ClassError,
    Utf8Error(Utf8Error),
    Domain(DomainError),
    NotYetImplemented,
    LengthError,

    AError,
    NSError,
    MDError,
    MFError,
    CNAMEError,
    SOAError,
    MBError,
    MGError,
    MRError,
    NULLError,
    WKSError,
    PTRError,
    HINFOError,
    MINFOError,
    MXError,
    TXTError,
    RPError,
    AFSDBError,
    X25Error,
    ISDNError,
    RTError,
    NSAPError,
    // TODO
    PXError,
    GPOSError,
    AAAAError,
    LOCError,
    // TODO
    EIDError,
    NIMLOCError,
    SRVError,
    // TODO
    KXError,
    // TODO
    DNAMEError,
    // TODO
    SSHFPError,
    // TODO
    MaxRecursionError,
}

impl From<Utf8Error> for DecodeError {
    fn from(utf8_error: Utf8Error) -> Self {
        DecodeError::Utf8Error(utf8_error)
    }
}

impl From<DomainError> for DecodeError {
    fn from(domain_error: DomainError) -> Self {
        DecodeError::Domain(domain_error)
    }
}
