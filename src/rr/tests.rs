use crate::{
    rr::{ServiceBinding, ServiceParameter},
    DomainName,
};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#aliasform
#[test]
fn test_https_alias_form() {
    // given
    let domain_name = "example.com".parse().unwrap();
    let target_name = "foo.example.com".parse().unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 0, // alias
        target_name,
        parameters: BTreeSet::default(),
        https: true,
    };

    // when
    let result = service_binding.to_string();

    // then
    assert_eq!(
        result,
        "example.com. 7200 IN HTTPS 0 foo.example.com.".to_string()
    );
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_svcb_use_the_ownername() {
    // given
    let domain_name = "example.com".parse().unwrap();
    let target_name = DomainName::default();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: BTreeSet::default(),
        https: false,
    };

    // when
    let result = service_binding.to_string();

    // then
    assert_eq!(result, "example.com. 300 IN SVCB 1 .");
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_https_map_port() {
    // given
    let domain_name = "example.com".parse().unwrap();
    let target_name = "foo.example.com".parse().unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 16,
        target_name,
        parameters: vec![ServiceParameter::PORT { port: 53 }]
            .into_iter()
            .collect::<BTreeSet<ServiceParameter>>(),
        https: true,
    };

    // when
    let result = service_binding.to_string();

    // then
    assert_eq!(
        result,
        "example.com. 7200 IN HTTPS 16 foo.example.com. port=53"
    );
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_svcb_unregistered_key_value() {
    // given
    let domain_name = "example.com".parse().unwrap();
    let target_name = "foo.example.com".parse().unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: vec![ServiceParameter::PRIVATE {
            number: 667,
            wire_data: b"hello".to_vec(),
        }]
        .into_iter()
        .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };

    // when
    let result = service_binding.to_string();

    // then
    assert_eq!(
        result,
        "example.com. 300 IN SVCB 1 foo.example.com. key667=hello"
    );
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_https_unregistered_key_escaped_value() {
    // given
    let domain_name = "example.com".parse().unwrap();
    let target_name = "foo.example.com".parse().unwrap();
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
        https: true,
    };

    // when
    let result = service_binding.to_string();

    // then
    assert_eq!(
        result,
        "example.com. 300 IN HTTPS 1 foo.example.com. key667=\"hello\\210qoo\""
    );
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_svcb_ipv6_hints() {
    // given
    let domain_name = "example.com".parse().unwrap();
    let target_name = "foo.example.com".parse().unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
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

    // when
    let result = service_binding.to_string();

    // then
    assert_eq!(
        result,
        "example.com. 7200 IN SVCB 1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\""
    );
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_https_ipv6_hint_in_ipv4_mapped_ipv6_format() {
    // given
    let domain_name = "example.com".parse().unwrap();
    let target_name = "foo.example.com".parse().unwrap();
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
        https: true,
    };

    // when
    let result = service_binding.to_string();

    // then
    // note IPv6 display rules are already well-defined so not changing that here
    // this behaviour conforms to the robustness principle
    assert_eq!(result,
               "example.com. 300 IN HTTPS 1 foo.example.com. ipv6hint=\"2001:db8:ffff:ffff:ffff:ffff:c633:6464\"");
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_svcb_multiple_parameters_in_wrong_order() {
    // given
    let domain_name = "example.org".parse().unwrap();
    let target_name = "foo.example.org".parse().unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 16,
        target_name,
        parameters: vec![
            // the parameters are deliberately specified in the wrong order
            // they will be sorted correctly in the presentation format
            ServiceParameter::ALPN {
                alpn_ids: vec!["h2".to_string(), "h3-19".to_string()],
            },
            ServiceParameter::MANDATORY {
                key_ids: vec![4, 1], // ipv4hint and alpn are mandatory
            },
            ServiceParameter::IPV4_HINT {
                hints: vec![Ipv4Addr::from_str("192.0.2.1").unwrap()],
            },
        ]
        .into_iter()
        .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };

    // when
    let result = service_binding.to_string();

    // then
    assert_eq!(result,
               "example.org. 7200 IN SVCB 16 foo.example.org. mandatory=alpn,ipv4hint alpn=h2,h3-19 ipv4hint=192.0.2.1");
}

/// Example from: https://github.com/MikeBishop/dns-alt-svc/blob/master/draft-ietf-dnsop-svcb-https.md#serviceform
#[test]
fn test_https_alpn_with_escaped_values() {
    // given
    let domain_name = "example.org".parse().unwrap();
    let target_name = "foo.example.org".parse().unwrap();
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
        https: true,
    };

    // when
    let result = service_binding.to_string();

    // then
    assert_eq!(
        result,
        "example.org. 300 IN HTTPS 16 foo.example.org. alpn=\"f\\\\\\\\oo\\,bar,h2\""
    );
}
