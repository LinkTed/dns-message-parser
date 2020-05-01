use bytes::Bytes;

use dns_message_parser::{Class, QClass, QClass_, QType, QType_, Type};

#[test]
fn decode_q_type_type() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x01"[..]);
    let mut offset = 0;
    let q_type = QType::decode(&bytes, &mut offset).unwrap();
    assert_eq!(q_type, QType::Type(Type::A));
}

#[test]
fn decode_q_type_q_type() {
    let bytes = Bytes::copy_from_slice(&b"\x00\xff"[..]);
    let mut offset = 0;
    let q_type = QType::decode(&bytes, &mut offset).unwrap();
    assert_eq!(q_type, QType::QType(QType_::ALL));
}

#[test]
fn decode_q_type_error() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let mut offset = 0;
    let result = QType::decode(&bytes, &mut offset);
    assert!(result.is_err());
}

#[test]
fn decode_q_class_class() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x03"[..]);
    let mut offset = 0;
    let q_class = QClass::decode(&bytes, &mut offset).unwrap();
    assert_eq!(q_class, QClass::Class(Class::CH));
}

#[test]
fn decode_q_class_q_class() {
    let bytes = Bytes::copy_from_slice(&b"\x00\xff"[..]);
    let mut offset = 0;
    let q_class = QClass::decode(&bytes, &mut offset).unwrap();
    assert_eq!(q_class, QClass::QClass(QClass_::ANY));
}

#[test]
fn decode_q_class_error() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let mut offset = 0;
    let result = QClass::decode(&bytes, &mut offset);
    assert!(result.is_err());
}
