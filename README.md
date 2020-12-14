# dns-message-parser
A library to encode and decode DNS packets ([RFC1035](https://tools.ietf.org/html/rfc1035), [RFC2535](https://tools.ietf.org/html/rfc2535)).

[![Build status](https://github.com/LinkTed/dns-message-parser/workflows/Continuous%20Integration/badge.svg)](https://github.com/LinkTed/dns-message-parser/actions?query=workflow%3A%22Continuous+Integration%22)
[![Dependency status](https://deps.rs/repo/github/linkted/dns-message-parser/status.svg)](https://deps.rs/repo/github/linkted/dns-message-parser)
[![Code coverage](https://codecov.io/gh/LinkTed/dns-message-parser/branch/master/graph/badge.svg)](https://codecov.io/gh/LinkTed/dns-message-parser)
[![Latest version](https://img.shields.io/crates/v/dns-message-parser.svg)](https://crates.io/crates/dns-message-parser)
[![License](https://img.shields.io/crates/l/dns-message-parser.svg)](https://opensource.org/licenses/BSD-3-Clause)  

**This library is not completed yet.**

## Usage
Add this to your `Cargo.toml`:
```toml
[dependencies]
dns-message-parser = "0.4"
```

## Example
```rust
use bytes::Bytes;
use dns_message_parser::{Dns, DomainName, Flags, Opcode, QClass, QType, Question, RCode};
use std::convert::TryFrom;

fn decode_example() {
    let msg = b"\xdb\x1c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a";

    let bytes = Bytes::copy_from_slice(&msg[..]);

    let dns = Dns::decode(bytes).unwrap();
    println!("{:?}", dns);
}

fn encode_example() {
    let id = 56092;
    let flags = Flags {
        qr: true,
        opcode: Opcode::Query,
        aa: true,
        tc: false,
        rd: true,
        ra: true,
        ad: false,
        cd: false,
        rcode: RCode::NoError,
    };
    let question = {
        let domain_name = DomainName::try_from("example.org.").unwrap();
        let q_class = QClass::IN;
        let q_type = QType::A;

        Question {
            domain_name,
            q_class,
            q_type,
        }
    };

    let questions = vec![question];
    let dns = Dns {
        id,
        flags,
        questions,
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let bytes = dns.encode().unwrap();
    println!("{:?}", bytes);
}
```
