use std::{convert::TryFrom, str::FromStr};

use bytes::Bytes;
use dns_message_parser::Dns;

fn decode_msg(msg: &[u8]) -> Dns {
    // Decode BytesMut to message
    let bytes = Bytes::copy_from_slice(msg);
    // Decode the DNS message
    Dns::decode(bytes).unwrap()
}

#[test]
fn request() {
    let msg = b"\xdb\x1c\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01";
    let dns = decode_msg(&msg[..]);
    assert!(!dns.is_response());
}

#[test]
fn response() {
    let msg = b"\xdb\x1c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a";
    let dns = decode_msg(&msg[..]);
    assert!(dns.is_response());
}

#[test]
fn example_net_edns_ede_forged() {
    let msg = b"\x16\x5a\x81\x83\x00\x01\x00\x00\x00\x00\x00\x02\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6e\x65\x74\x00\x00\x01\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x06\x00\x01\x00\x09\
    \x3a\x80\x00\x1e\xc0\x1d\x05\x65\x6d\x61\x69\x6c\xc0\x1d\x00\x00\x00\x02\x00\x09\x3a\x80\x00\x01\x51\x80\x00\x24\
    \xea\x00\x00\x09\x3a\x80\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x08\x00\x0f\x00\x04\x00\x12\x41\x41";
    let dns = decode_msg(&msg[..]);
    assert_eq!(
        dns,
        dns_message_parser::Dns {
            id: 5722,
            flags: dns_message_parser::Flags {
                qr: true,
                opcode: dns_message_parser::Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                ad: false,
                cd: false,
                rcode: dns_message_parser::RCode::NXDomain
            },
            questions: vec![dns_message_parser::question::Question {
                domain_name: dns_message_parser::DomainName::from_str("example.net").unwrap(),
                q_class: dns_message_parser::question::QClass::IN,
                q_type: dns_message_parser::question::QType::A
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![
                dns_message_parser::rr::RR::SOA(dns_message_parser::rr::SOA {
                    domain_name: dns_message_parser::DomainName::from_str("example.org").unwrap(),
                    ttl: 604800,
                    class: dns_message_parser::rr::Class::IN,
                    m_name: dns_message_parser::DomainName::from_str("example.org").unwrap(),
                    r_name: dns_message_parser::DomainName::from_str("email.example.org").unwrap(),
                    serial: 2,
                    refresh: 604800,
                    retry: 86400,
                    expire: 2419200,
                    min_ttl: 604800
                }),
                dns_message_parser::rr::RR::OPT(dns_message_parser::rr::OPT {
                    requestor_payload_size: 1232,
                    extend_rcode: 0,
                    version: 0,
                    dnssec: false,
                    edns_options: vec![
                        dns_message_parser::rr::edns::EDNSOption::ExtendedDNSErrors(
                            dns_message_parser::rr::edns::ExtendedDNSErrors {
                                info_code:
                                    dns_message_parser::rr::edns::ExtendedDNSErrorCodes::Prohibited,
                                extra_text:
                                    dns_message_parser::rr::edns::ExtendedDNSErrorExtraText::try_from("AA").unwrap(),
                            }
                        )
                    ]
                })
            ]
        }
    );
}
