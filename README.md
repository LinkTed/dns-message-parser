# dns-message-parser
A library to encode and decode DNS packets ([RFC1035](https://tools.ietf.org/html/rfc1035), [RFC2535](https://tools.ietf.org/html/rfc2535)).

[![Build Status](https://travis-ci.org/LinkTed/dns-message-parser.svg?branch=master)](https://travis-ci.org/LinkTed/dns-message-parser)
[![dependency status](https://deps.rs/repo/github/linkted/dns-message-parser/status.svg)](https://deps.rs/repo/github/linkted/dns-message-parser)
[![Latest version](https://img.shields.io/crates/v/dns-message-parser.svg)](https://crates.io/crates/dns-message-parser)
[![License](https://img.shields.io/crates/l/dns-message-parser.svg)](https://opensource.org/licenses/BSD-3-Clause)  

**This library is not completed yet.**

## Usage
Add this to your `Cargo.toml`:
```toml
[dependencies]
dns-message-parser = "0.1"
```

## Example
```rust
use bytes::{Bytes, BytesMut};

use dns_message_parser::{
    Class, Dns, DomainName, Flags, Opcode, QClass, QType, Question, RCode, Type,
};

fn decode_example() {
    let msg = b"\xdb\x1c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a";

    let bytes = Bytes::copy_from_slice(&msg[..]);

    let dns = Dns::decode(&bytes).unwrap();
    println!("{:?}", dns);
}

fn encode_example() {
    let id = 56092;
    let flags = Flags::new(
        true,
        Opcode::Query,
        true,
        false,
        true,
        true,
        false,
        false,
        RCode::NoError,
    );
    let question = {
        let mut domain_name = DomainName::default();
        domain_name.append_label("example");
        domain_name.append_label("org");

        let qclass = QClass::Class(Class::IN);

        let qtype = QType::Type(Type::A);

        Question::new(domain_name, qclass, qtype)
    };

    let questions = vec![question];
    let dns = Dns::new(id, flags, questions, Vec::new(), Vec::new(), Vec::new());
    let mut bytes = BytesMut::new();
    dns.encode(&mut bytes).unwrap();
    println!("{:?}", dns);
}
```
