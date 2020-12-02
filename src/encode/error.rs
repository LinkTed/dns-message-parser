use crate::rr::{
    AFSDBSubtype, AddressNumber, Class, EDNSOptionCode, SSHFPAlgorithm, SSHFPType, Type,
};
use crate::{QClass, QType};

#[derive(Debug, PartialEq)]
pub enum EncodeError {
    StringError(usize),
    OffsetError(usize),
    TooMuchData(usize),
    NotEnoughData,
    QTypeError(QType),
    QClassError(QClass),
    TypeError(Type),
    ClassError(Class),
    OpcodeError,
    RCodeError,
    NotYetImplemented,
    CompressionError(u16),
    MaxRecursionError(usize),
    AFSDBSubtypeError(AFSDBSubtype),
    SSHFPAlgorithmError(SSHFPAlgorithm),
    SSHFPTypeError(SSHFPType),
    AddressNumberError,
    EDNSOptionCodeError(EDNSOptionCode),
    ECSSourcePrefixLengthError(u8),
    ECSAddressNumberError(AddressNumber),
    CookieServerLengthError(usize),
}
