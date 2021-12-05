use dns_message_parser::{
    question::{QClass, QType, Question},
    {Dns, Flags, Opcode, RCode},
};

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
        let domain_name = "example.org.".parse().unwrap();
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
