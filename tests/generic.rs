use bytes::Bytes;
use dns_message_parser::{
    question::{QClass, QType, Question},
    rr::{Class, Type, A, RR},
    {DomainName, Label},
};
use std::net::Ipv4Addr;

fn get_question_example_org() -> Question {
    let mut domain_name = DomainName::default();
    domain_name
        .append_label("example".parse().unwrap())
        .unwrap();
    domain_name.append_label("org".parse().unwrap()).unwrap();

    let q_class = QClass::IN;
    let q_type = QType::A;

    Question {
        domain_name,
        q_class,
        q_type,
    }
}

#[test]
fn question() {
    let question = get_question_example_org();
    let bytes = question.encode().unwrap();

    assert_eq!(
        bytes,
        &b"\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x01"[..]
    );
}

#[test]
fn resource_record() {
    let mut domain_name = DomainName::default();
    domain_name
        .append_label("example".parse().unwrap())
        .unwrap();
    domain_name.append_label("org".parse().unwrap()).unwrap();
    let ipv4_addr = Ipv4Addr::new(10, 0, 0, 10);
    let ttl_1 = 3600;
    let rr_1 = RR::A(A {
        domain_name,
        ttl: ttl_1,
        ipv4_addr,
    });

    let bytes = rr_1.encode().unwrap();

    assert_eq!(
        bytes,
        &b"\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x0e\x10\
        \x00\x04\x0a\x00\x00\x0a"[..]
    );
}

#[test]
fn decode_type_type() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x01"[..]);
    let type_ = Type::decode(bytes).unwrap();
    assert_eq!(type_, Type::A);
}

#[test]
fn decode_type_error() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let result = Type::decode(bytes);
    assert!(result.is_err());
}

#[test]
fn decode_class() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x03"[..]);
    let class = Class::decode(bytes).unwrap();
    assert_eq!(class, Class::CH);
}

#[test]
fn decode_class_error() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let result = Class::decode(bytes);
    assert!(result.is_err());
}

#[test]
fn domain_name_eq() {
    let domain_name_1: DomainName = "Example.OrG.".parse().unwrap();
    let domain_name_2 = "example.org".parse().unwrap();
    let domain_name_3 = "example.com.".parse().unwrap();
    assert_eq!(domain_name_1, domain_name_2);
    assert_ne!(domain_name_1, domain_name_3);
}

#[test]
fn label_eq() {
    let label: Label = "Example".parse().unwrap();
    assert_eq!(label, "example");
    assert_eq!(label.as_ref(), "Example");
    assert_eq!(label, "example");
}

#[test]
fn domain_name_to_string() {
    let domain_name: DomainName = "Example.OrG.".parse().unwrap();
    let domain_name = domain_name.to_string();
    assert_eq!(&domain_name, "Example.OrG.");
}
