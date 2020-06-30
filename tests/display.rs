use dns_message_parser::{
    Class, Dns, DomainName, Flags, Opcode, QClass, QClass_, QType, QType_, Question, RCode, RData,
    Type, RR,
};

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
fn r_data_a() {
    let ipv4_addr = "10.0.0.1".parse().unwrap();
    let r_data = RData::A(ipv4_addr);
    check_output(&r_data, "A 10.0.0.1");
}

#[test]
fn r_data_ns() {
    let ns_d_name = DomainName::try_from("ns1.example.org").unwrap();
    let r_data = RData::NS(ns_d_name);
    check_output(&r_data, "NS ns1.example.org.");
}

#[test]
fn r_data_cname() {
    let ns_d_name = DomainName::try_from("example.org").unwrap();
    let r_data = RData::CNAME(ns_d_name);
    check_output(&r_data, "CNAME example.org.");
}

#[test]
fn r_data_soa() {
    let m_name = DomainName::try_from("ns1.example.org.").unwrap();
    let r_name = DomainName::try_from("admin.example.org.").unwrap();
    let serial = 1;
    let refresh = 10800;
    let retry = 3600;
    let expire = 604800;
    let min_ttl = 3600;
    let r_data = RData::SOA(m_name, r_name, serial, refresh, retry, expire, min_ttl);
    check_output(
        &r_data,
        "SOA ns1.example.org. admin.example.org. (1 10800 3600 604800 3600)",
    );
}

#[test]
fn r_data_mb() {
    let mad_name = DomainName::try_from("mail.example.org").unwrap();
    let r_data = RData::MB(mad_name);
    check_output(&r_data, "MB mail.example.org.");
}

#[test]
fn r_data_mg() {
    let mgm_name = DomainName::try_from("mail.example.org").unwrap();
    let r_data = RData::MG(mgm_name);
    check_output(&r_data, "MG mail.example.org.");
}

#[test]
fn r_data_mr() {
    let new_name = DomainName::try_from("mail.example.org").unwrap();
    let r_data = RData::MR(new_name);
    check_output(&r_data, "MR mail.example.org.");
}

// TODO WKS

#[test]
fn r_data_ptr() {
    let ptr_d_name = DomainName::try_from("example.org").unwrap();
    let r_data = RData::PTR(ptr_d_name);
    check_output(&r_data, "PTR example.org.");
}

#[test]
fn r_data_hinfo() {
    let cpu = String::from("TEST");
    let os = String::from("Linux");
    let r_data = RData::HINFO(cpu, os);
    check_output(&r_data, "HINFO \"TEST\" \"Linux\"");
}

#[test]
fn r_data_minfo() {
    let r_mail_bx = DomainName::try_from("admin.example.org").unwrap();
    let e_mail_bx = DomainName::try_from("error.example.org").unwrap();
    let r_data = RData::MINFO(r_mail_bx, e_mail_bx);
    check_output(&r_data, "MINFO admin.example.org. error.example.org.");
}

#[test]
fn r_data_mx() {
    let preference = 10;
    let exchange = DomainName::try_from("mail.example.org").unwrap();
    let r_data = RData::MX(preference, exchange);
    check_output(&r_data, "MX 10 mail.example.org.");
}

#[test]
fn r_data_txt() {
    let string = String::from("Text");
    let r_data = RData::TXT(string);
    check_output(&r_data, "TXT \"Text\"");
}

#[test]
fn r_data_rp() {
    let mbox_dname = DomainName::try_from("admin.example.org").unwrap();
    let txt_dname = DomainName::try_from("error.example.org").unwrap();
    let r_data = RData::RP(mbox_dname, txt_dname);
    check_output(&r_data, "RP admin.example.org. error.example.org.");
}

#[test]
fn r_data_x25() {
    let psdn_address = String::from("311061700956");
    let r_data = RData::X25(psdn_address);
    check_output(&r_data, "X25 311061700956");
}

#[test]
fn r_data_isdn_1() {
    let isdn_address = String::from("150862028003217");
    let sa = Some(String::from("004"));
    let r_data = RData::ISDN(isdn_address, sa);
    check_output(&r_data, "ISDN 150862028003217 004");
}

#[test]
fn r_data_isdn_2() {
    let isdn_address = String::from("150862028003217");
    let sa = None;
    let r_data = RData::ISDN(isdn_address, sa);
    check_output(&r_data, "ISDN 150862028003217");
}

#[test]
fn r_data_rt() {
    let preference = 2;
    let exchange = DomainName::try_from("relay.example.org").unwrap();
    let r_data = RData::RT(preference, exchange);
    check_output(&r_data, "RT 2 relay.example.org.");
}

#[test]
fn r_data_px() {
    let preference = 10;
    let map822 = DomainName::try_from("example.org").unwrap();
    let mapx400 = DomainName::try_from("px400.example.org").unwrap();
    let r_data = RData::PX(preference, map822, mapx400);
    check_output(&r_data, "PX 10 example.org. px400.example.org.");
}

#[test]
fn r_data_gpos() {
    let longitude = String::from("-32.0082");
    let latitude = String::from("120.0050");
    let altitude = String::from("10.0");
    let r_data = RData::GPOS(longitude, latitude, altitude);
    check_output(&r_data, "GPOS \"-32.0082\" \"120.0050\" \"10.0\"");
}

#[test]
fn r_data_aaaa() {
    let ipv6_addr = "::1".parse().unwrap();
    let r_data = RData::AAAA(ipv6_addr);
    check_output(&r_data, "AAAA ::1");
}

#[test]
fn r_data_eid() {
    let data = Vec::from(&b"\xe3\x2c\x6f\x78\x16\x3a\x93\x48"[..]);
    let r_data = RData::EID(data);
    check_output(&r_data, "EID e32c6f78163a9348");
}

#[test]
fn r_data_nimloc() {
    let data = Vec::from(&b"\x32\x25\x1a\x03\x00\x67"[..]);
    let r_data = RData::NIMLOC(data);
    check_output(&r_data, "NIMLOC 32251a030067");
}

#[test]
fn r_data_srv() {
    let priority = 0;
    let weight = 1;
    let port = 80;
    let target = DomainName::try_from("srv.example.org").unwrap();
    let r_data = RData::SRV(priority, weight, port, target);
    check_output(&r_data, "SRV 0 1 80 srv.example.org.");
}

#[test]
fn r_data_kx() {
    let preference = 10;
    let exchanger = DomainName::try_from("kx.example.org").unwrap();
    let r_data = RData::KX(preference, exchanger);
    check_output(&r_data, "KX 10 kx.example.org.");
}

#[test]
fn r_data_dname() {
    let target = DomainName::try_from("dname.example.org").unwrap();
    let r_data = RData::DNAME(target);
    check_output(&r_data, "DNAME dname.example.org.");
}

#[test]
fn resource_record() {
    let domain_name = DomainName::try_from("example.org.").unwrap();
    let class = Class::IN;
    let ttl = 3600;
    let ipv4_addr = "10.0.0.10".parse().unwrap();
    let r_data = RData::A(ipv4_addr);
    let resource_record = RR::new(domain_name, class, ttl, r_data);
    check_output(&resource_record, "example.org. 3600 IN A 10.0.0.10");
}

#[test]
fn q_type_type() {
    let q_type = QType::Type(Type::A);
    check_output(&q_type, "A");
}

#[test]
fn q_type_q_type() {
    let q_type = QType::QType(QType_::ALL);
    check_output(&q_type, "ALL");
}

#[test]
fn q_class_class() {
    let q_type = QClass::Class(Class::IN);
    check_output(&q_type, "IN");
}

#[test]
fn q_class_q_class() {
    let q_type = QClass::QClass(QClass_::ANY);
    check_output(&q_type, "ANY");
}

#[test]
fn question() {
    let domain_name = DomainName::try_from("example.org.").unwrap();
    let q_class = QClass::Class(Class::IN);
    let q_type = QType::Type(Type::A);
    let question = Question::new(domain_name, q_class, q_type);
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
        let q_class = QClass::Class(Class::IN);
        let q_type = QType::Type(Type::CNAME);
        vec![Question::new(domain_name, q_class, q_type)]
    };
    let answers = {
        let domain_name = DomainName::try_from("cname.example.org.").unwrap();
        let class = Class::IN;
        let ttl = 3600;
        let cname = DomainName::try_from("example.org.").unwrap();
        let r_data = RData::CNAME(cname);
        vec![RR::new(domain_name, class, ttl, r_data)]
    };
    let authorities = {
        let domain_name = DomainName::try_from("ns1.example.org.").unwrap();
        let class = Class::IN;
        let ttl = 3600;
        let ns = DomainName::try_from("example.org.").unwrap();
        let r_data = RData::NS(ns);
        vec![RR::new(domain_name, class, ttl, r_data)]
    };
    let additionals = {
        let domain_name = DomainName::try_from("example.org.").unwrap();
        let class = Class::IN;
        let ttl = 3600;
        let ipv4_addr = "10.0.0.10".parse().unwrap();
        let r_data = RData::A(ipv4_addr);
        vec![RR::new(domain_name, class, ttl, r_data)]
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
