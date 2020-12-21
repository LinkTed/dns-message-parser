use crate::encode::Encoder;
use crate::DomainName;
use std::convert::TryFrom;

#[test]
fn test_domain_name_encoding_nothing() {
    let mut encoder = Encoder::default();

    let mut domain_name = DomainName::default();
    domain_name.append_label("mail").unwrap();
    domain_name.append_label("ns").unwrap();
    domain_name.append_label("google").unwrap();
    domain_name.append_label("com").unwrap();
    encoder.domain_name(&domain_name).unwrap();

    let domain = DomainName::try_from("mail.ns.google.org.").unwrap();
    encoder.domain_name(&domain).unwrap();

    assert_eq!(
        encoder.bytes,
        &b"\x04mail\x02ns\x06google\x03com\0\x04mail\x02ns\x06google\x03org\0"[..]
    );
}

#[test]
fn test_domain_name_encoding_partially() {
    let mut encoder = Encoder::default();

    let mut domain_name = DomainName::default();
    domain_name.append_label("mail").unwrap();
    domain_name.append_label("ns").unwrap();
    domain_name.append_label("google").unwrap();
    domain_name.append_label("com").unwrap();
    encoder.domain_name(&domain_name).unwrap();

    let domain_name = DomainName::try_from("com").unwrap();
    encoder.domain_name(&domain_name).unwrap();

    assert_eq!(
        encoder.bytes,
        &b"\x04mail\x02ns\x06google\x03com\0\xc0\x0f"[..]
    );
}

#[test]
fn test_domain_name_encoding_completely() {
    let mut encoder = Encoder::default();

    let mut domain_name = DomainName::default();
    domain_name.append_label("mail").unwrap();
    domain_name.append_label("ns").unwrap();
    domain_name.append_label("google").unwrap();
    domain_name.append_label("com").unwrap();
    encoder.domain_name(&domain_name).unwrap();

    let domain_name = DomainName::try_from("mail.ns.google.com.").unwrap();
    encoder.domain_name(&domain_name).unwrap();

    assert_eq!(
        encoder.bytes,
        &b"\x04mail\x02ns\x06google\x03com\0\xc0\0"[..]
    );
}

#[test]
fn test_domain_name_encoding_recursive() {
    let mut encoder = Encoder::default();

    let mut d1 = DomainName::default();
    d1.append_label("google").unwrap();
    d1.append_label("com").unwrap();
    encoder.domain_name(&d1).unwrap();

    let d2 = DomainName::try_from("mail1.ns.google.com").unwrap();
    encoder.domain_name(&d2).unwrap();

    let d3 = DomainName::try_from("mail2.ns.google.com.").unwrap();
    encoder.domain_name(&d3).unwrap();

    assert_eq!(
        encoder.bytes,
        &b"\x06google\x03com\0\x05mail1\x02ns\xc0\0\x05mail2\xc0\x12"[..],
    );
}

#[test]
fn test_domain_name_encode_root() {
    let domain_name = DomainName::default();
    let bytes = domain_name.encode().unwrap();
    assert_eq!(bytes, &b"\0"[..]);
}

#[test]
fn test_domain_name_encode_com() {
    let mut domain_name = DomainName::default();
    domain_name.append_label("com").unwrap();
    let bytes = domain_name.encode().unwrap();
    assert_eq!(bytes, &b"\x03com\0"[..]);
}

#[test]
fn test_domain_name_encode_google_com() {
    let mut domain_name = DomainName::default();
    domain_name.append_label("google").unwrap();
    domain_name.append_label("com").unwrap();
    let bytes = domain_name.encode().unwrap();
    assert_eq!(bytes, &b"\x06google\x03com\0"[..]);
}
