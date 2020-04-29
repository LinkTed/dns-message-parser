#[derive(Debug)]
pub enum EncodeError {
    TooMuchData,
    QTypeError,
    TypeError,
    QClassError,
    ClassError,
    OpcodeError,
    RCodeError,
    NotYetImplemented,
    CompressionError,
    AFSDBSubtypeError,
    SSHFPAlgorithmError,
    SSHFPTypeError,
}
