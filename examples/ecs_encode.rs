use dns_message_parser::{
    question::{QClass, QType, Question},
    rr::edns::{EDNSOption, ECS},
    rr::{Address, A, OPT, RR},
    {Dns, Flags, Opcode, RCode},
};

fn main() {
    let id = 32042;
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

    let q_a = {
        let domain_name = "example.org.".parse().unwrap();
        let q_class = QClass::IN;
        let q_type = QType::A;

        Question {
            domain_name,
            q_class,
            q_type,
        }
    };
    let questions = vec![q_a];

    let rr_a = {
        let domain_name = "example.org.".parse().unwrap();
        let ttl = 3600;
        let ipv4_addr = "10.0.0.10".parse().unwrap();
        let a = A {
            domain_name,
            ttl,
            ipv4_addr,
        };
        RR::A(a)
    };
    let answers = vec![rr_a];

    // Create the EDNS structs
    let rr_opt = {
        let requestor_payload_size = 1232;
        let extend_rcode = 0;
        let version = 0;
        let dnssec = false;
        // Create EDNS Client Subnet
        let edns_ecs = {
            let address = Address::Ipv4("10.0.0.0".parse().unwrap());
            // source_prefix_length = 12
            // scope_prefix_length  = 24
            // adress               = 127.0.0.1
            let ecs = ECS::new(12, 24, address).unwrap();
            EDNSOption::ECS(ecs)
        };
        let edns_options = vec![edns_ecs];
        let opt = OPT {
            requestor_payload_size,
            extend_rcode,
            version,
            dnssec,
            edns_options,
        };
        RR::OPT(opt)
    };
    let additionals = vec![rr_opt];

    let dns = Dns {
        id,
        flags,
        questions,
        answers,
        authorities: Vec::new(),
        additionals,
    };

    let bytes = dns.encode().unwrap();
    println!("{:x}", bytes);
}
