use bytes::Bytes;
use dns_message_parser::question::{QClass, QType};

#[test]
fn decode_q_type_type() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x01"[..]);
    let q_type = QType::decode(bytes).unwrap();
    assert_eq!(q_type, QType::A);
}

#[test]
fn decode_q_type_q_type() {
    let bytes = Bytes::copy_from_slice(&b"\x00\xff"[..]);
    let q_type = QType::decode(bytes).unwrap();
    assert_eq!(q_type, QType::ALL);
}

#[test]
fn decode_q_type_error() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let result = QType::decode(bytes);
    assert!(result.is_err());
}

#[test]
fn decode_q_class_class() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x03"[..]);
    let q_class = QClass::decode(bytes).unwrap();
    assert_eq!(q_class, QClass::CH);
}

#[test]
fn decode_q_class_q_class() {
    let bytes = Bytes::copy_from_slice(&b"\x00\xff"[..]);
    let q_class = QClass::decode(bytes).unwrap();
    assert_eq!(q_class, QClass::ANY);
}

#[test]
fn decode_q_class_error() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let result = QClass::decode(bytes);
    assert!(result.is_err());
}

#[test]
fn decode_q_type_svcb() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x40"[..]);
    let q_type = QType::decode(bytes).unwrap();
    assert_eq!(q_type, QType::SVCB);
}

#[test]
fn decode_q_type_https() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x41"[..]);
    let q_type = QType::decode(bytes).unwrap();
    assert_eq!(q_type, QType::HTTPS);
}
