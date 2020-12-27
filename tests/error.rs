use dns_message_parser::rr::edns::{Cookie, CookieError, ECS};
use dns_message_parser::rr::{Address, AddressError};
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn opt_cookie_server_cookie_length() {
    let client_cookie = b"\xd5\xa7\xe3\x00\x4d\x79\x05\x1e".to_owned();
    let server_cookie = Some(b"\x01\x00\x00\x00".to_vec());
    let cookie = Cookie::new(client_cookie, server_cookie);
    assert_eq!(cookie, Err(CookieError::ServerCookieLength(4)))
}

#[test]
fn opt_ecs_set_source_prefix_length() {
    let ipv4_addr: Ipv4Addr = "10.0.0.0".parse().unwrap();
    let address = Address::Ipv4(ipv4_addr);
    let mut ecs = ECS::new(24, 0, address).unwrap();
    assert_eq!(
        ecs.set_source_prefix_length(1),
        Err(AddressError::Ipv4Mask(ipv4_addr, 1))
    )
}

#[test]
fn opt_ecs_set_scope_prefix_length() {
    let ipv4_addr: Ipv4Addr = "10.0.0.0".parse().unwrap();
    let address = Address::Ipv4(ipv4_addr);
    let mut ecs = ECS::new(24, 0, address).unwrap();
    assert_eq!(
        ecs.set_source_prefix_length(33),
        Err(AddressError::Ipv4Prefix(33))
    )
}

#[test]
fn opt_ecs_set_address() {
    let ipv6_addr: Ipv6Addr = "1122::".parse().unwrap();
    let address = Address::Ipv6(ipv6_addr);
    let mut ecs = ECS::new(24, 0, address).unwrap();
    let ipv6_addr: Ipv6Addr = "1122:3344:5566:7788:99::".parse().unwrap();
    let address = Address::Ipv6(ipv6_addr);
    assert_eq!(
        ecs.set_address(address),
        Err(AddressError::Ipv6Mask(ipv6_addr, 24))
    )
}
