use bytes::{Bytes, BytesMut};

use dns_message_parser::{Class, DomainName, QClass, QType, Question, RData, Type, RR};

use std::collections::HashMap;
use std::net::Ipv4Addr;

fn get_question_example_org() -> Question {
    let mut domain_name = DomainName::default();
    domain_name.append_label("example").unwrap();
    domain_name.append_label("org").unwrap();

    let qclass = QClass::Class(Class::IN);
    let qtype = QType::Type(Type::A);

    Question::new(domain_name, qclass, qtype)
}

#[test]
fn question() {
    let mut bytes = BytesMut::new();
    let mut compression = HashMap::new();

    let question = get_question_example_org();
    let result = question.encode(&mut bytes, &mut compression);
    assert!(result.is_ok());

    assert_eq!(
        bytes,
        &b"\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x01"[..]
    );
}

#[test]
fn resource_record() {
    let mut bytes = BytesMut::new();
    let mut compression = HashMap::new();

    let mut domain_name = DomainName::default();
    domain_name.append_label("example").unwrap();
    domain_name.append_label("org").unwrap();

    let ipv_4_addr = Ipv4Addr::new(10, 0, 0, 10);

    let ttl_1 = 3600;

    let r_data_1 = RData::A(ipv_4_addr);

    let rr = RR::new(domain_name, Class::IN, ttl_1, r_data_1.clone());

    let result = rr.encode(&mut bytes, &mut compression);
    assert!(result.is_ok());

    assert_eq!(
        bytes,
        &b"\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x0e\x10\
        \x00\x04\x0a\x00\x00\x0a"[..]
    );

    let question_1 = get_question_example_org();

    let (question_2, ttl_2, r_data_2) = rr.split();

    assert_eq!(question_1, question_2);
    assert_eq!(ttl_1, ttl_2);
    assert_eq!(r_data_1, r_data_2);
}

#[test]
fn label_64() {
    let mut domain_name = DomainName::default();
    let result = domain_name
        .append_label("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(result.is_err());
}

#[test]
fn domain_name_max_length() {
    let mut domain_name = DomainName::default();
    domain_name
        .append_label("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .unwrap();
    domain_name
        .append_label("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .unwrap();
    domain_name
        .append_label("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .unwrap();
    domain_name
        .append_label("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .unwrap();
    let result = domain_name.append_label("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(result.is_err());
}

#[test]
fn domain_name_regex() {
    let mut domain_name = DomainName::default();
    let result = domain_name.append_label(".");
    assert!(result.is_err());
}

#[test]
fn decode_type_type() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x01"[..]);
    let mut offset = 0;
    let type_ = Type::decode(&bytes, &mut offset).unwrap();
    assert_eq!(type_, Type::A);
}

#[test]
fn decode_type_error() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let mut offset = 0;
    let result = Type::decode(&bytes, &mut offset);
    assert!(result.is_err());
}

#[test]
fn decode_class() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x03"[..]);
    let mut offset = 0;
    let class = Class::decode(&bytes, &mut offset).unwrap();
    assert_eq!(class, Class::CH);
}

#[test]
fn decode_class_error() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let mut offset = 0;
    let result = Class::decode(&bytes, &mut offset);
    assert!(result.is_err());
}
