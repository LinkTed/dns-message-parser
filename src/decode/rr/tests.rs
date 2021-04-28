use super::Header;
use crate::decode::decoder::Decoder;
use crate::decode::error::DecodeError::ECHLengthMismatch;
use crate::rr::ServiceParameter;
use crate::{DecodeError, DomainName};
use bytes::Bytes;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[test]
fn header_get_class_error() {
    let header = Header {
        domain_name: DomainName::default(),
        class: u16::MAX,
        ttl: 1000,
    };
    assert_eq!(header.get_class(), Err(DecodeError::Class(u16::MAX)));
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#aliasform
#[test]
fn test_service_binding_alias_form() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x00"); // priority
    bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 0);
    assert_eq!(
        result.target_name,
        DomainName::try_from("foo.example.com").unwrap()
    );
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert!(result.parameters.is_empty());
    assert!(result.to_string().ends_with("0 foo.example.com."));
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_use_the_ownername() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x01"); // priority
    bytes.extend_from_slice(b"\x00"); // target (root label)
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 1);
    assert_eq!(result.target_name, DomainName::try_from(".").unwrap());
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert!(result.parameters.is_empty());
    assert!(result.to_string().ends_with("1 ."));
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_map_port() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x10"); // priority
    bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
    bytes.extend_from_slice(b"\x00\x03"); // key 3 (port)
    bytes.extend_from_slice(b"\x00\x02"); // value length: 2 bytes (2 octets)
    bytes.extend_from_slice(b"\x00\x35"); // value: 53
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 16);
    assert_eq!(
        result.target_name,
        DomainName::try_from("foo.example.com").unwrap()
    );
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert_eq!(result.parameters.len(), 1);
    assert!(matches!(result.parameters.iter().next().unwrap(),
        ServiceParameter::PORT {port} if *port == 53));
    assert!(result.to_string().ends_with("16 foo.example.com. port=53"));
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_unregistered_key() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x01"); // priority
    bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
    bytes.extend_from_slice(b"\x02\x9b"); // key 667 (unregistered)
    bytes.extend_from_slice(b"\x00\x05"); // value length: 5 bytes (2 octets)
    bytes.extend_from_slice(b"hello"); // value
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 1);
    assert_eq!(
        result.target_name,
        DomainName::try_from("foo.example.com").unwrap()
    );
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert_eq!(result.parameters.len(), 1);
    assert!(matches!(result.parameters.iter().next().unwrap(),
            ServiceParameter::PRIVATE { number, wire_data, } if *number == 667
                && String::from_utf8(wire_data.clone()).unwrap() == *"hello"))
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_unregistered_key_escaped_value() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x01"); // priority
    bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
    bytes.extend_from_slice(b"\x02\x9b"); // key 667 (unregistered)
    bytes.extend_from_slice(b"\x00\x09"); // value length: 9 bytes (2 octets)
    bytes.extend_from_slice(b"hello\xd2qoo"); // value
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 1);
    assert_eq!(
        result.target_name,
        DomainName::try_from("foo.example.com").unwrap()
    );
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert_eq!(result.parameters.len(), 1);
    assert!(matches!(result.parameters.iter().next().unwrap(),
            ServiceParameter::PRIVATE { number, wire_data, } if *number == 667
                && wire_data.as_slice() == b"hello\xd2qoo"));
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_ipv6_hints() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x01"); // priority
    bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
    bytes.extend_from_slice(b"\x00\x06"); // key 6 (IPv6 hint)
    bytes.extend_from_slice(b"\x00\x20"); // value length: 32 bytes (2 octets)
    bytes.extend_from_slice(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"); // first address
    bytes.extend_from_slice(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01"); // second address
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 1);
    assert_eq!(
        result.target_name,
        DomainName::try_from("foo.example.com").unwrap()
    );
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert_eq!(result.parameters.len(), 1);
    assert!(matches!(result.parameters.iter().next().unwrap(),
            ServiceParameter::IPV6_HINT { hints } if hints.len() == 2
                && hints[0] == Ipv6Addr::from_str("2001:db8::1").unwrap()
                && hints[1] == Ipv6Addr::from_str("2001:db8::53:1").unwrap()));
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_ipv6_in_ipv4_mapped_ipv6_format() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x01"); // priority
    bytes.extend_from_slice(b"\x07example\x03com\x00"); // target
    bytes.extend_from_slice(b"\x00\x06"); // key 6 (IPv6 hint)
    bytes.extend_from_slice(b"\x00\x10"); // value length: 16 bytes (2 octets)
    bytes.extend_from_slice(b"\x20\x01\x0d\xb8\xff\xff\xff\xff\xff\xff\xff\xff\xc6\x33\x64\x64"); // address
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 1);
    assert_eq!(
        result.target_name,
        DomainName::try_from("example.com").unwrap()
    );
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert_eq!(result.parameters.len(), 1);
    assert!(matches!(result.parameters.iter().next().unwrap(),
             ServiceParameter::IPV6_HINT { hints } if hints.len() == 1 && hints[0] == Ipv6Addr::from_str("2001:db8:ffff:ffff:ffff:ffff:198.51.100.100").unwrap()))
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_multiple_parameters() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x10"); // priority
    bytes.extend_from_slice(b"\x03foo\x07example\x03org\x00"); // target

    // parameters are deliberately presented in the incorrect order
    // they will be sorted correctly when they are deserialised
    bytes.extend_from_slice(b"\x00\x01"); // key 1 (alpn)
    bytes.extend_from_slice(b"\x00\x09"); // alpn value length: 9 bytes (2 octets)
    bytes.extend_from_slice(b"\x02"); // alpn[0] length: 2 bytes (1 octet)
    bytes.extend_from_slice(b"h2"); // alpn[0] = h2
    bytes.extend_from_slice(b"\x05"); // alpn[1] length: 5 bytes (1 octet)
    bytes.extend_from_slice(b"h3-19"); // alpn[1] = h3-19
    bytes.extend_from_slice(b"\x00\x00"); // key 0 (mandatory)
    bytes.extend_from_slice(b"\x00\x02"); // value length: 2 bytes (2 octets)
    bytes.extend_from_slice(b"\x00\x01"); // value: key 1
    bytes.extend_from_slice(b"\x00\x04"); // key 4 (IPv4 hint)
    bytes.extend_from_slice(b"\x00\x04"); // hint length: 4 bytes (2 octets)
    bytes.extend_from_slice(b"\xc0\x00\x02\x01"); // IPv4 address
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 16);
    assert_eq!(
        result.target_name,
        DomainName::try_from("foo.example.org").unwrap()
    );
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert_eq!(result.parameters.len(), 3);
    let mut parameters = result.parameters.iter();
    assert!(matches!(parameters.next().unwrap(),
            ServiceParameter::MANDATORY{ key_ids } if key_ids.len() == 1 && key_ids[ 0 ] == 1 ));
    assert!(matches!(parameters.next().unwrap(),
            ServiceParameter::ALPN { alpn_ids } if alpn_ids.len() == 2 && alpn_ids[0] == "h2" && alpn_ids[1] == "h3-19"));
    assert!(matches!(parameters.next().unwrap(),
            ServiceParameter::IPV4_HINT { hints } if hints.len() == 1 && hints[0] == Ipv4Addr::from_str("192.0.2.1").unwrap()));
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_escaped_presentation_format() {
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x10"); // priority
    bytes.extend_from_slice(b"\x03foo\x07example\x03org\x00"); // target
    bytes.extend_from_slice(b"\x00\x01"); // key 1 (alpn)
    bytes.extend_from_slice(b"\x00\x0c"); // param length 12
    bytes.extend_from_slice(b"\x08"); // alpn[0] length 8
    bytes.extend_from_slice(b"f\\oo,bar"); // alpn[0]
    bytes.extend_from_slice(b"\x02"); // alpn[1] length 2
    bytes.extend_from_slice(b"h2"); // alpn[1]

    let mut decoder = Decoder::main(Bytes::from(bytes));

    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false).unwrap();

    // then
    assert_eq!(result.priority, 16);
    assert_eq!(
        result.target_name,
        DomainName::try_from("foo.example.org").unwrap()
    );
    assert_eq!(result.ttl, 7200);
    assert_eq!(
        result.name,
        DomainName::try_from("test.example.com").unwrap()
    );
    assert_eq!(result.parameters.len(), 1);
    assert!(matches!(result.parameters.iter().next().unwrap(),
            ServiceParameter::ALPN { alpn_ids } if alpn_ids.len() == 2 && alpn_ids[0] == "f\\oo,bar" && alpn_ids[1] == "h2"));
}

#[test]
fn test_service_binding_ech_length_mismatch() {
    // given
    let mut bytes: Vec<u8> = vec![];
    bytes.extend_from_slice(b"\x00\x01"); // priority
    bytes.extend_from_slice(b"\x03foo\x07example\x03com\x00"); // target
    bytes.extend_from_slice(b"\x00\x05"); // key 5 (ECH)
    bytes.extend_from_slice(b"\x00\x07"); // value length: 7 bytes (2 octets)
    bytes.extend_from_slice(b"\x00\x07"); // (incorrect) ECHConfigList length: 7 bytes (2 octets)
    bytes.extend_from_slice(b"Hello"); // value
    let mut decoder = Decoder::main(Bytes::from(bytes));
    let header = Header {
        domain_name: DomainName::try_from("test.example.com").unwrap(),
        class: 1,
        ttl: 7200,
    };

    // when
    let result = decoder.rr_service_binding(header, false);

    // then
    assert!(matches!(result,
        Err(decode_error) if matches!(decode_error,
            ECHLengthMismatch(expected, actual) if expected == 7 && actual == 5)));
}
