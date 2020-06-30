use bytes::BytesMut;
use dns_message_parser::{
    Class, Dns, DomainName, Flags, Opcode, QClass, QType, Question, RCode, Type,
};
use std::convert::TryFrom;

fn main() {
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

        let qclass = QClass::Class(Class::IN);

        let qtype = QType::Type(Type::A);

        Question::new(domain_name, qclass, qtype)
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
    let mut bytes = BytesMut::new();
    dns.encode(&mut bytes).unwrap();
    println!("{:?}", bytes);
}
