use bytes::BytesMut;

use crate::DomainName;

use std::collections::HashMap;
use std::convert::TryFrom;

use super::{encode_string, EncodeError};

#[test]
fn test_domain_name_encoding_nothing() {
    let mut bytes = BytesMut::new();
    let offset = bytes.len();
    let mut compression = HashMap::new();
    let mut domain = DomainName::default();
    domain.append_label("mail").unwrap();
    domain.append_label("ns").unwrap();
    domain.append_label("google").unwrap();
    domain.append_label("com").unwrap();

    let result = domain.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    let domain = DomainName::try_from("mail.ns.google.org.").unwrap();

    let result = domain.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    assert_eq!(
        bytes,
        &b"\x04mail\x02ns\x06google\x03com\0\x04mail\x02ns\x06google\x03org\0"[..]
    );
}

#[test]
fn test_domain_name_encoding_partially() {
    let mut bytes = BytesMut::new();
    let offset = bytes.len();
    let mut compression = HashMap::new();
    let mut domain = DomainName::default();
    domain.append_label("mail").unwrap();
    domain.append_label("ns").unwrap();
    domain.append_label("google").unwrap();
    domain.append_label("com").unwrap();

    let result = domain.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    let domain = DomainName::try_from("com").unwrap();

    let result = domain.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    assert_eq!(bytes, &b"\x04mail\x02ns\x06google\x03com\0\xc0\x0f"[..]);
}

#[test]
fn test_domain_name_encoding_completely() {
    let mut bytes = BytesMut::new();
    let offset = bytes.len();
    let mut compression = HashMap::new();
    let mut domain = DomainName::default();
    domain.append_label("mail").unwrap();
    domain.append_label("ns").unwrap();
    domain.append_label("google").unwrap();
    domain.append_label("com").unwrap();

    let result = domain.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    let domain = DomainName::try_from("mail.ns.google.com.").unwrap();

    let result = domain.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    assert_eq!(bytes, &b"\x04mail\x02ns\x06google\x03com\0\xc0\0"[..]);
}

#[test]
fn test_domain_name_encoding_recursive() {
    let mut bytes = BytesMut::new();
    let offset = bytes.len();
    let mut compression = HashMap::new();
    let mut d1 = DomainName::default();
    d1.append_label("google").unwrap();
    d1.append_label("com").unwrap();

    let result = d1.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    let d2 = DomainName::try_from("mail1.ns.google.com").unwrap();

    let result = d2.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    let d3 = DomainName::try_from("mail2.ns.google.com.").unwrap();

    let result = d3.encode(&mut bytes, &offset, &mut compression);
    assert!(result.is_ok());

    let bytes = bytes.freeze();
    let mut offset = 0;
    let d1_ = DomainName::decode(&bytes, &mut offset).unwrap();
    let d2_ = DomainName::decode(&bytes, &mut offset).unwrap();
    let d3_ = DomainName::decode(&bytes, &mut offset).unwrap();

    assert_eq!(d1, d1_);
    assert_eq!(d2, d2_);
    assert_eq!(d3, d3_);
}

#[test]
fn test_domain_name_encode_root() {
    let mut bytes = BytesMut::new();
    let offset = bytes.len();
    let mut compression = HashMap::new();
    let domain_name = DomainName::default();
    domain_name
        .encode(&mut bytes, &offset, &mut compression)
        .unwrap();
    assert_eq!(bytes, &b"\0"[..]);
}

#[test]
fn test_domain_name_encode_com() {
    let mut bytes = BytesMut::new();
    let offset = bytes.len();
    let mut compression = HashMap::new();
    let mut domain_name = DomainName::default();
    domain_name.append_label("com").unwrap();
    domain_name
        .encode(&mut bytes, &offset, &mut compression)
        .unwrap();
    assert_eq!(bytes, &b"\x03com\0"[..]);
}

#[test]
fn test_domain_name_encode_google_com() {
    let mut bytes = BytesMut::new();
    let offset = bytes.len();
    let mut compression = HashMap::new();
    let mut domain_name = DomainName::default();
    domain_name.append_label("google").unwrap();
    domain_name.append_label("com").unwrap();
    domain_name
        .encode(&mut bytes, &offset, &mut compression)
        .unwrap();
    assert_eq!(bytes, &b"\x06google\x03com\0"[..]);
}

#[test]
fn string_error() {
    let mut bytes = BytesMut::new();
    let string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let result = encode_string(&mut bytes, string);
    assert_eq!(result, Err(EncodeError::TooMuchData));
}
