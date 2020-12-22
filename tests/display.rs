use dns_message_parser::question::{QClass, QType, Question};
use dns_message_parser::rr::{
    Address, Class, EDNSOption, ISDNAddress, PSDNAddress, SSHFPAlgorithm, SSHFPType, A, AAAA,
    CNAME, DNAME, ECS, EID, EUI48, EUI64, GPOS, HINFO, ISDN, KX, MB, MD, MF, MG, MINFO, MR, MX,
    NIMLOC, NS, OPT, PTR, PX, RP, RR, RT, SA, SOA, SRV, SSHFP, TXT, URI, X25,
};
use dns_message_parser::{Dns, DomainName, Flags, Opcode, RCode};
use std::convert::TryFrom;
use std::fmt::Display;

fn check_output<T>(t: &T, output: &str)
where
    T: Display,
{
    let format = format!("{}", t);
    assert_eq!(&format, output);
}

#[test]
fn rr_a() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let ipv4_addr = "10.0.0.1".parse().unwrap();
    let rr = RR::A(A {
        domain_name,
        ttl: 100,
        ipv4_addr,
    });
    check_output(&rr, "example.org. 100 IN A 10.0.0.1");
}

#[test]
fn rr_ns() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let ns_d_name = DomainName::try_from("ns1.example.org").unwrap();
    let rr = RR::NS(NS {
        domain_name,
        ttl: 100,
        class,
        ns_d_name,
    });
    check_output(&rr, "example.org. 100 CS NS ns1.example.org.");
}

#[test]
fn rr_cname() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let c_name = DomainName::try_from("example.org").unwrap();
    let rr = RR::CNAME(CNAME {
        domain_name,
        ttl: 100,
        class,
        c_name,
    });
    check_output(&rr, "example.org. 100 IN CNAME example.org.");
}

#[test]
fn rr_soa() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let m_name = DomainName::try_from("ns1.example.org.").unwrap();
    let r_name = DomainName::try_from("admin.example.org.").unwrap();
    let serial = 1;
    let refresh = 10800;
    let retry = 3600;
    let expire = 604800;
    let min_ttl = 3600;
    let rr = RR::SOA(SOA {
        domain_name,
        ttl: 100,
        class,
        m_name,
        r_name,
        serial,
        refresh,
        retry,
        expire,
        min_ttl,
    });
    check_output(
        &rr,
        "example.org. 100 CH SOA ns1.example.org. admin.example.org. (1 10800 3600 604800 3600)",
    );
}

#[test]
fn rr_mb() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let mad_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MB(MB {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    check_output(&rr, "example.org. 100 HS MB mail.example.org.");
}

#[test]
fn rr_md() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let mad_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MD(MD {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    check_output(&rr, "example.org. 100 HS MD mail.example.org.");
}

#[test]
fn rr_mf() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let mad_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MF(MF {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    check_output(&rr, "example.org. 100 HS MF mail.example.org.");
}

#[test]
fn rr_mg() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let mgm_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MG(MG {
        domain_name,
        ttl: 100,
        class,
        mgm_name,
    });
    check_output(&rr, "example.org. 100 IN MG mail.example.org.");
}

#[test]
fn rr_mr() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let new_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MR(MR {
        domain_name,
        ttl: 100,
        class,
        new_name,
    });
    check_output(&rr, "example.org. 100 CS MR mail.example.org.");
}

// TODO WKS

#[test]
fn rr_ptr() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let ptr_d_name = DomainName::try_from("example.org").unwrap();
    let rr = RR::PTR(PTR {
        domain_name,
        ttl: 100,
        class,
        ptr_d_name,
    });
    check_output(&rr, "example.org. 100 CH PTR example.org.");
}

#[test]
fn rr_hinfo() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let cpu = String::from("TEST");
    let os = String::from("Linux");
    let rr = RR::HINFO(HINFO {
        domain_name,
        ttl: 100,
        class,
        cpu,
        os,
    });
    check_output(&rr, "example.org. 100 HS HINFO TEST Linux");
}

#[test]
fn rr_minfo() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let r_mail_bx = DomainName::try_from("admin.example.org").unwrap();
    let e_mail_bx = DomainName::try_from("error.example.org").unwrap();
    let rr = RR::MINFO(MINFO {
        domain_name,
        ttl: 100,
        class,
        r_mail_bx,
        e_mail_bx,
    });
    check_output(
        &rr,
        "example.org. 100 IN MINFO admin.example.org. error.example.org.",
    );
}

#[test]
fn rr_mx() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let preference = 10;
    let exchange = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MX(MX {
        domain_name,
        ttl: 100,
        class,
        preference,
        exchange,
    });
    check_output(&rr, "example.org. 100 CS MX 10 mail.example.org.");
}

#[test]
fn rr_txt() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let string = String::from("Text");
    let rr = RR::TXT(TXT {
        domain_name,
        ttl: 100,
        class,
        string,
    });
    check_output(&rr, "example.org. 100 CH TXT Text");
}

#[test]
fn rr_rp() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let mbox_dname = DomainName::try_from("admin.example.org").unwrap();
    let txt_dname = DomainName::try_from("error.example.org").unwrap();
    let rr = RR::RP(RP {
        domain_name,
        ttl: 100,
        class,
        mbox_dname,
        txt_dname,
    });
    check_output(
        &rr,
        "example.org. 100 HS RP admin.example.org. error.example.org.",
    );
}

#[test]
fn rr_x25() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let psdn_address = PSDNAddress::try_from(String::from("311061700956")).unwrap();
    let rr = RR::X25(X25 {
        domain_name,
        ttl: 100,
        class,
        psdn_address,
    });
    check_output(&rr, "example.org. 100 IN X25 311061700956");
}

#[test]
fn rr_isdn_1() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let isdn_address = ISDNAddress::try_from(String::from("150862028003217")).unwrap();
    let sa = Some(SA::try_from(String::from("004")).unwrap());
    let rr = RR::ISDN(ISDN {
        domain_name,
        ttl: 100,
        class,
        isdn_address,
        sa,
    });
    check_output(&rr, "example.org. 100 CS ISDN 150862028003217 004");
}

#[test]
fn rr_isdn_2() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let isdn_address = ISDNAddress::try_from(String::from("150862028003217")).unwrap();
    let sa = None;
    let rr = RR::ISDN(ISDN {
        domain_name,
        ttl: 100,
        class,
        isdn_address,
        sa,
    });
    check_output(&rr, "example.org. 100 CH ISDN 150862028003217");
}

#[test]
fn rr_rt() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let preference = 2;
    let intermediate_host = DomainName::try_from("relay.example.org").unwrap();
    let rr = RR::RT(RT {
        domain_name,
        ttl: 100,
        class,
        preference,
        intermediate_host,
    });
    check_output(&rr, "example.org. 100 HS RT 2 relay.example.org.");
}

#[test]
fn rr_px() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let preference = 10;
    let map822 = DomainName::try_from("example.org").unwrap();
    let mapx400 = DomainName::try_from("px400.example.org").unwrap();
    let rr = RR::PX(PX {
        domain_name,
        ttl: 100,
        class,
        preference,
        map822,
        mapx400,
    });
    check_output(
        &rr,
        "example.org. 100 IN PX 10 example.org. px400.example.org.",
    );
}

#[test]
fn rr_gpos() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let longitude = String::from("-32.0082");
    let latitude = String::from("120.0050");
    let altitude = String::from("10.0");
    let rr = RR::GPOS(GPOS {
        domain_name,
        ttl: 100,
        class,
        longitude,
        latitude,
        altitude,
    });
    check_output(&rr, "example.org. 100 CS GPOS -32.0082 120.0050 10.0");
}

#[test]
fn rr_aaaa() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let ipv6_addr = "::1".parse().unwrap();
    let rr = RR::AAAA(AAAA {
        domain_name,
        ttl: 100,
        ipv6_addr,
    });
    check_output(&rr, "example.org. 100 IN AAAA ::1");
}

#[test]
fn rr_eid() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let data = Vec::from(&b"\xe3\x2c\x6f\x78\x16\x3a\x93\x48"[..]);
    let rr = RR::EID(EID {
        domain_name,
        ttl: 100,
        class,
        data,
    });
    check_output(&rr, "example.org. 100 CH EID e32c6f78163a9348");
}

#[test]
fn rr_nimloc() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let data = Vec::from(&b"\x32\x25\x1a\x03\x00\x67"[..]);
    let rr = RR::NIMLOC(NIMLOC {
        domain_name,
        ttl: 100,
        class,
        data,
    });
    check_output(&rr, "example.org. 100 HS NIMLOC 32251a030067");
}

#[test]
fn rr_srv() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let priority = 0;
    let weight = 1;
    let port = 80;
    let target = DomainName::try_from("srv.example.org").unwrap();
    let rr = RR::SRV(SRV {
        domain_name,
        ttl: 100,
        class,
        priority,
        weight,
        port,
        target,
    });
    check_output(&rr, "example.org. 100 IN SRV 0 1 80 srv.example.org.");
}

#[test]
fn rr_kx() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let preference = 10;
    let exchanger = DomainName::try_from("kx.example.org").unwrap();
    let rr = RR::KX(KX {
        domain_name,
        ttl: 100,
        class,
        preference,
        exchanger,
    });
    check_output(&rr, "example.org. 100 CS KX 10 kx.example.org.");
}

#[test]
fn rr_dname() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let target = DomainName::try_from("dname.example.org").unwrap();
    let rr = RR::DNAME(DNAME {
        domain_name,
        ttl: 100,
        class,
        target,
    });
    check_output(&rr, "example.org. 100 CH DNAME dname.example.org.");
}

#[test]
fn rr_sshfp() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let algorithm = SSHFPAlgorithm::DSS;
    let type_ = SSHFPType::Sha1;
    let fp = b"\x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90\x12\x34\x56\x78\x9a\xbc\xde\xf6\x78\x90"
        .to_vec();
    let rr = RR::SSHFP(SSHFP {
        domain_name,
        ttl: 100,
        class,
        algorithm,
        type_,
        fp,
    });
    check_output(
        &rr,
        "example.org. 100 HS SSHFP DSS Sha1 123456789abcdef67890123456789abcdef67890",
    );
}

#[test]
fn rr_eui48() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let eui_48 = b"\x00\x11\x22\x33\x44\x55".to_owned();
    let rr = RR::EUI48(EUI48 {
        domain_name,
        ttl: 100,
        class,
        eui_48,
    });
    check_output(&rr, "example.org. 100 CS EUI48 00-11-22-33-44-55");
}

#[test]
fn rr_eui64() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let eui_64 = b"\x00\x11\x22\x33\x44\x55\x66\x77".to_owned();
    let rr = RR::EUI64(EUI64 {
        domain_name,
        ttl: 100,
        class,
        eui_64,
    });
    check_output(&rr, "example.org. 100 CH EUI64 00-11-22-33-44-55-66-77");
}

#[test]
fn rr_uri() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let uri = "https://example.org/".to_string();
    let rr = RR::URI(URI {
        domain_name,
        ttl: 100,
        class,
        priority: 1,
        weight: 10,
        uri,
    });
    check_output(&rr, "example.org. 100 IN URI 1 10 https://example.org/");
}

#[test]
fn rr_opt_ecs_1() {
    let address = Address::Ipv4("10.0.0.0".parse().unwrap());
    let ecs = ECS::new(24, 24, address).unwrap();
    let rr = RR::OPT(OPT {
        requestor_payload_size: 1024,
        dnssec: false,
        version: 0,
        extend_rcode: 0,
        edns_options: vec![EDNSOption::ECS(ecs)],
    });
    check_output(&rr, ". 0 IN OPT 1024 0 0 false 24 24 10.0.0.0");
}

#[test]
fn rr_opt_ecs_2() {
    let address = Address::Ipv6("10::".parse().unwrap());
    let ecs = ECS::new(24, 24, address).unwrap();
    let rr = RR::OPT(OPT {
        requestor_payload_size: 1024,
        dnssec: false,
        version: 0,
        extend_rcode: 0,
        edns_options: vec![EDNSOption::ECS(ecs)],
    });
    check_output(&rr, ". 0 IN OPT 1024 0 0 false 24 24 10::");
}

#[test]
fn q_type_type() {
    let q_type = QType::A;
    check_output(&q_type, "A");
}

#[test]
fn q_type_q_type() {
    let q_type = QType::ALL;
    check_output(&q_type, "ALL");
}

#[test]
fn q_class_class() {
    let q_type = QClass::IN;
    check_output(&q_type, "IN");
}

#[test]
fn q_class_q_class() {
    let q_type = QClass::ANY;
    check_output(&q_type, "ANY");
}

#[test]
fn question() {
    let domain_name = DomainName::try_from("example.org.").unwrap();
    let q_class = QClass::IN;
    let q_type = QType::A;
    let question = Question {
        domain_name,
        q_class,
        q_type,
    };
    check_output(&question, "example.org. IN A")
}

#[test]
fn flags() {
    let opcode = Opcode::Query;
    let rcode = RCode::NoError;
    let flags = Flags {
        qr: true,
        opcode,
        aa: true,
        tc: true,
        rd: true,
        ra: true,
        ad: true,
        cd: true,
        rcode,
    };
    check_output(&flags, "qr Query aa tc rd ra ad cd NoError");
}

#[test]
fn dns() {
    let id = 10105;
    let opcode = Opcode::Query;
    let rcode = RCode::NoError;
    let flags = Flags {
        qr: false,
        opcode,
        aa: false,
        tc: false,
        rd: false,
        ra: false,
        ad: false,
        cd: false,
        rcode,
    };
    let questions = {
        let domain_name = DomainName::try_from("cname.example.org.").unwrap();
        let q_class = QClass::IN;
        let q_type = QType::CNAME;
        let question = Question {
            domain_name,
            q_class,
            q_type,
        };
        vec![question]
    };
    let answers = {
        let domain_name = DomainName::try_from("cname.example.org.").unwrap();
        let class = Class::IN;
        let ttl = 3600;
        let c_name = DomainName::try_from("example.org.").unwrap();
        let c_name = CNAME {
            domain_name,
            ttl,
            class,
            c_name,
        };
        vec![RR::CNAME(c_name)]
    };
    let authorities = {
        let domain_name = DomainName::try_from("ns1.example.org.").unwrap();
        let class = Class::IN;
        let ttl = 3600;
        let ns_d_name = DomainName::try_from("example.org.").unwrap();
        let ns = NS {
            domain_name,
            class,
            ttl,
            ns_d_name,
        };
        vec![RR::NS(ns)]
    };
    let additionals = {
        let domain_name = DomainName::try_from("example.org.").unwrap();
        let ttl = 3600;
        let ipv4_addr = "10.0.0.10".parse().unwrap();
        let a = A {
            domain_name,
            ttl,
            ipv4_addr,
        };
        vec![RR::A(a)]
    };
    let dns = Dns {
        id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    };
    check_output(
        &dns,
        "10105 Query NoError questions [cname.example.org. IN CNAME, ] \
        answers [cname.example.org. 3600 IN CNAME example.org., ] \
        authorities [ns1.example.org. 3600 IN NS example.org., ] \
        additionals [example.org. 3600 IN A 10.0.0.10, ]",
    );
}
