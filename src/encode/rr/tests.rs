use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::encode::encoder::Encoder;
use crate::question::QType::{HTTPS, SVCB};
use crate::question::{QClass, Question};
use crate::rr::{ServiceBinding, ServiceBindingMode, ServiceParameter, RR};
use crate::{Dns, DomainName, Flags, Opcode, RCode};
use std::collections::BTreeSet;

#[test]
fn test_service_binding_encode_decode() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("_8765._baz.api.test").unwrap();
    let target_name = DomainName::try_from("svc4-baz.test").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 0,
        target_name,
        parameters: BTreeSet::default(),
        https: false,
    };
    let dns = service_binding_dns(0xeced, service_binding);

    // when
    encoder.dns(&dns).unwrap();

    // then
    let result = Dns::decode(encoder.bytes.freeze()).expect("Unable to parse encoded DNS");
    assert_eq!(result.answers.len(), 1);
    let answer = &result.answers[0];
    assert!(
        matches!(answer, RR::SVCB(service_binding) if service_binding.mode() == ServiceBindingMode::Alias)
    )
}

/// Example from https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#aliasform
#[test]
fn test_service_binding_alias_form() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.com").unwrap();
    let target_name = DomainName::try_from("foo.example.com").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 0,
        target_name,
        parameters: BTreeSet::default(),
        https: false,
    };
    let dns = service_binding_dns(0xcccd, service_binding);

    // when
    encoder.dns(&dns).unwrap();

    // then
    let mut expected = vec![];
    expected.extend_from_slice(b"\x00\x00"); // priority
    expected.extend_from_slice(b"\x03foo"); // target subdomain (new data)
    expected.extend_from_slice(b"\xc0\x0c"); // target parent domain (compressed format, first appears at index 12)

    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - expected.len());
    assert_eq!(suffix, expected.as_slice());
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_use_the_owername() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.test").unwrap();
    let target_name = DomainName::default();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 1,
        target_name,
        parameters: BTreeSet::default(),
        https: false,
    };
    let dns = service_binding_dns(0xccce, service_binding);

    // when
    encoder.dns(&dns).unwrap();

    // then
    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - 3);
    assert_eq!(suffix, b"\x00\x01\x00");
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_map_port() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.com").unwrap();
    let target_name = DomainName::try_from("foo.example.com").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 16,
        target_name,
        parameters: vec![ServiceParameter::PORT { port: 53 }]
            .into_iter()
            .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };
    let dns = service_binding_dns(0xcddc, service_binding);
    // when
    encoder.dns(&dns).unwrap();

    // then
    let mut expected = vec![];
    expected.extend_from_slice(b"\x00\x10"); // priority
    expected.extend_from_slice(b"\x03foo"); // target subdomain (new data)
    expected.extend_from_slice(b"\xc0\x0c"); // target parent domain (compressed format, first appears at index 12)
    expected.extend_from_slice(b"\x00\x03"); // key 3 (port)
    expected.extend_from_slice(b"\x00\x02"); // value length (2 bytes)
    expected.extend_from_slice(b"\x00\x35"); // value (port 53)

    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - expected.len());
    assert_eq!(suffix, expected.as_slice());
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_unregistered_key_value() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.com").unwrap();
    let target_name = DomainName::try_from("foo.example.com").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 16,
        target_name,
        parameters: vec![ServiceParameter::PRIVATE {
            number: 667,
            wire_data: b"hello".to_vec(),
        }]
        .into_iter()
        .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };
    let dns = service_binding_dns(0xcfcc, service_binding);
    // when
    encoder.dns(&dns).unwrap();

    // then
    let mut expected = vec![];
    expected.extend_from_slice(b"\x00\x10"); // priority
    expected.extend_from_slice(b"\x03foo"); // target subdomain (new data)
    expected.extend_from_slice(b"\xc0\x0c"); // target parent domain (compressed format, first appears at index 12)
    expected.extend_from_slice(b"\x02\x9b"); // key 667
    expected.extend_from_slice(b"\x00\x05"); // value length (5)
    expected.extend_from_slice(b"hello"); // value

    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - expected.len());
    assert_eq!(suffix, expected.as_slice());
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_unregistered_key_unquoted_value() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.com").unwrap();
    let target_name = DomainName::try_from("foo.example.com").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: vec![ServiceParameter::PRIVATE {
            number: 667,
            wire_data: b"hello\xd2qoo".to_vec(),
        }]
        .into_iter()
        .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };
    let dns = service_binding_dns(0xdffd, service_binding);
    // when
    encoder.dns(&dns).unwrap();

    // then
    let mut expected = vec![];
    expected.extend_from_slice(b"\x00\x01"); // priority
    expected.extend_from_slice(b"\x03foo"); // target subdomain (new data)
    expected.extend_from_slice(b"\xc0\x0c"); // target parent domain (compressed format, first appears at index 12)
    expected.extend_from_slice(b"\x02\x9b"); // key 667
    expected.extend_from_slice(b"\x00\x09"); // value length (5)
    expected.extend_from_slice(b"hello\xd2qoo"); // value

    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - expected.len());
    assert_eq!(suffix, expected.as_slice());
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_ipv6_hints() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.com").unwrap();
    let target_name = DomainName::try_from("foo.example.com").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: vec![ServiceParameter::IPV6_HINT {
            hints: vec![
                Ipv6Addr::from_str("2001:db8::1").unwrap(),
                Ipv6Addr::from_str("2001:db8::53:1").unwrap(),
            ],
        }]
        .into_iter()
        .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };
    let dns = service_binding_dns(0xacca, service_binding);

    // when
    encoder.dns(&dns).unwrap();

    // then
    let mut expected = vec![];
    expected.extend_from_slice(b"\x00\x01"); // priority
    expected.extend_from_slice(b"\x03foo"); // target subdomain (new data)
    expected.extend_from_slice(b"\xc0\x0c"); // target parent domain (compressed format, first appears at index 12)
    expected.extend_from_slice(b"\x00\x06"); // key 6 (IPv6 hints)
    expected.extend_from_slice(b"\x00\x20"); // length 32
    expected.extend_from_slice(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"); // first IP address
    expected.extend_from_slice(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01"); // second IP address

    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - expected.len());
    assert_eq!(suffix, expected.as_slice());
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_ipv6_hint_in_ipv4_mapped_ipv6_presentation_format() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.com").unwrap();
    let target_name = DomainName::try_from("example.com").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: vec![ServiceParameter::IPV6_HINT {
            hints: vec![Ipv6Addr::from_str("2001:db8:ffff:ffff:ffff:ffff:198.51.100.100").unwrap()],
        }]
        .into_iter()
        .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };
    let dns = service_binding_dns(0xaedc, service_binding);

    // when
    encoder.dns(&dns).unwrap();

    // then
    let mut expected = vec![];
    expected.extend_from_slice(b"\x00\x01"); // priority
    expected.extend_from_slice(b"\xc0\x0c"); // target domain (compressed format, first appears at index 12)
    expected.extend_from_slice(b"\x00\x06"); // key 6 (IPv6 hints)
    expected.extend_from_slice(b"\x00\x10"); // length 16
    expected.extend_from_slice(b"\x20\x01\x0d\xb8\xff\xff\xff\xff\xff\xff\xff\xff\xc6\x33\x64\x64"); // IP address

    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - expected.len());
    assert_eq!(suffix, expected.as_slice());
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_sort_multiple_parameters() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.org").unwrap();
    let target_name = DomainName::try_from("foo.example.org").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 16,
        target_name,
        // parameters are deliberately presented in the incorrect order
        // they will be sorted correctly prior to sending over the wire
        parameters: vec![
            ServiceParameter::ALPN {
                alpn_ids: vec!["h2".to_string(), "h3-19".to_string()],
            },
            ServiceParameter::MANDATORY {
                key_ids: vec![4, 1],
            },
            ServiceParameter::IPV4_HINT {
                hints: vec![Ipv4Addr::from_str("192.0.2.1").unwrap()],
            },
        ]
        .into_iter()
        .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };
    let dns = service_binding_dns(0xadda, service_binding);

    // when
    encoder.dns(&dns).unwrap();

    // then
    let mut expected = vec![];
    expected.extend_from_slice(b"\x00\x10"); // priority
    expected.extend_from_slice(b"\x03foo"); // target subdomain (new data)
    expected.extend_from_slice(b"\xc0\x0c"); // target parent domain (compressed format, first appears at index 12)
    expected.extend_from_slice(b"\x00\x00"); // key 0 (mandatory keys)
    expected.extend_from_slice(b"\x00\x04"); // value length (2 mandatory keys)
    expected.extend_from_slice(b"\x00\x01"); // alpn is mandatory
    expected.extend_from_slice(b"\x00\x04"); // ipv4hint is mandatory
    expected.extend_from_slice(b"\x00\x01"); // key 1 (alpn)
    expected.extend_from_slice(b"\x00\x09"); // value length (9)
    expected.extend_from_slice(b"\x02"); // alpn ID length (2)
    expected.extend_from_slice(b"h2"); // alpn_ids[0] = h2
    expected.extend_from_slice(b"\x05"); // alpn ID length (2)
    expected.extend_from_slice(b"h3-19"); // alpn_ids[1] = h3-19
    expected.extend_from_slice(b"\x00\x04"); // key 4 (ipv4hint)
    expected.extend_from_slice(b"\x00\x04"); // value length 4 (1 IPv4 address)
    expected.extend_from_slice(b"\xc0\x00\x02\x01"); // IP address

    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - expected.len());
    assert_eq!(suffix, expected.as_slice());
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_service_binding_alpn_with_escaped_values() {
    // given
    let mut encoder = Encoder::default();
    let domain_name = DomainName::try_from("example.org").unwrap();
    let target_name = DomainName::try_from("foo.example.org").unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 16,
        target_name,
        parameters: vec![ServiceParameter::ALPN {
            alpn_ids: vec!["f\\oo,bar".to_string(), "h2".to_string()],
        }]
        .into_iter()
        .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };
    let dns = service_binding_dns(0xdfaf, service_binding);

    // when
    encoder.dns(&dns).unwrap();

    // then
    let mut expected = vec![];
    expected.extend_from_slice(b"\x00\x10"); // priority
    expected.extend_from_slice(b"\x03foo"); // target subdomain (new data)
    expected.extend_from_slice(b"\xc0\x0c"); // target parent domain (compressed format, first appears at index 12)
    expected.extend_from_slice(b"\x00\x01"); // key 1 (alpn)
    expected.extend_from_slice(b"\x00\x0c"); // value length (12)
    expected.extend_from_slice(b"\x08"); // alpn ID length (8)
    expected.extend_from_slice(b"f\\oo,bar"); // alpn_ids[0] = f\oo,bar
    expected.extend_from_slice(b"\x02"); // alpn ID length (2)
    expected.extend_from_slice(b"h2"); // alpn_ids[1] = h2

    let (_, suffix) = encoder.bytes.split_at(encoder.bytes.len() - expected.len());
    assert_eq!(suffix, expected.as_slice());
}

fn service_binding_dns(id: u16, service_binding: ServiceBinding) -> Dns {
    Dns {
        id,
        flags: response_flag(),
        questions: vec![Question {
            domain_name: service_binding.name.to_owned(),
            q_class: QClass::IN,
            q_type: if service_binding.https { HTTPS } else { SVCB },
        }],
        answers: vec![if service_binding.https {
            RR::HTTPS(service_binding)
        } else {
            RR::SVCB(service_binding)
        }],
        authorities: vec![],
        additionals: vec![],
    }
}

fn response_flag() -> Flags {
    Flags {
        qr: true,
        opcode: Opcode::Query,
        aa: false,
        tc: false,
        rd: false,
        ra: false,
        ad: false,
        cd: false,
        rcode: RCode::NoError,
    }
}
