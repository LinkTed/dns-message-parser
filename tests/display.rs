use dns_message_parser::{
    question::{QClass, QType, Question},
    rr::{
        edns::{
            Cookie, EDNSOption, ExtendedDNSErrorCodes, ExtendedDNSErrorExtraText,
            ExtendedDNSErrors, Padding, ECS,
        },
        APItem, Address, AlgorithmType, Class, DigestType, ISDNAddress, PSDNAddress,
        SSHFPAlgorithm, SSHFPType, ServiceBinding, ServiceParameter, Tag, A, AAAA, APL, CAA, CNAME,
        DNAME, DNSKEY, DS, EID, EUI48, EUI64, GPOS, HINFO, ISDN, KX, L32, L64, LP, MB, MD, MF, MG,
        MINFO, MR, MX, NID, NIMLOC, NS, OPT, PTR, PX, RP, RR, RT, SA, SOA, SRV, SSHFP, TXT, URI,
        X25,
    },
    Dns, Flags, Opcode, RCode,
};
use std::{
    collections::BTreeSet,
    convert::{TryFrom, TryInto},
    fmt::Display,
};

fn check_output<T>(t: &T, output: &str)
where
    T: Display,
{
    let format = format!("{}", t);
    assert_eq!(&format, output);
}

#[test]
fn rr_a() {
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let ns_d_name = "ns1.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let c_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let m_name = "ns1.example.org.".parse().unwrap();
    let r_name = "admin.example.org.".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let mad_name = "mail.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let mad_name = "mail.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let mad_name = "mail.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let mgm_name = "mail.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let new_name = "mail.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let ptr_d_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let r_mail_bx = "admin.example.org".parse().unwrap();
    let e_mail_bx = "error.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let preference = 10;
    let exchange = "mail.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let strings = vec![String::from("Text\n")].try_into().unwrap();
    let rr = RR::TXT(TXT {
        domain_name,
        ttl: 100,
        class,
        strings,
    });
    check_output(&rr, "example.org. 100 CH TXT \"Text\\n\"");
}

#[test]
fn rr_rp() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let mbox_dname = "admin.example.org".parse().unwrap();
    let txt_dname = "error.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let preference = 2;
    let intermediate_host = "relay.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let preference = 10;
    let map822 = "example.org".parse().unwrap();
    let mapx400 = "px400.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let priority = 0;
    let weight = 1;
    let port = 80;
    let target = "srv.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let preference = 10;
    let exchanger = "kx.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let target = "dname.example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
fn rr_nid() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let preference = 10;
    let node_id = 0xffeeddccbbaa9988;
    let rr = RR::NID(NID {
        domain_name,
        ttl: 100,
        class,
        preference,
        node_id,
    });
    check_output(&rr, "example.org. 100 CH NID 10 ffee:ddcc:bbaa:9988");
}

#[test]
fn rr_l32() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let preference = 10;
    let locator_32 = 0x0a000001;
    let rr = RR::L32(L32 {
        domain_name,
        ttl: 100,
        class,
        preference,
        locator_32,
    });
    check_output(&rr, "example.org. 100 HS L32 10 10.0.0.1");
}

#[test]
fn rr_l64() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let preference = 100;
    let locator_64 = 0x2021222324252627;
    let rr = RR::L64(L64 {
        domain_name,
        ttl: 200,
        class,
        preference,
        locator_64,
    });
    check_output(&rr, "example.org. 200 IN L64 100 2021:2223:2425:2627");
}

#[test]
fn rr_lp() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let preference = 200;
    let fqdn = "l64-subnet.example.org.".parse().unwrap();
    let rr = RR::LP(LP {
        domain_name,
        ttl: 100,
        class,
        preference,
        fqdn,
    });
    check_output(&rr, "example.org. 100 CS LP 200 l64-subnet.example.org.");
}

#[test]
fn rr_eui48() {
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    let domain_name = "example.org".parse().unwrap();
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
    check_output(&rr, ". OPT 1024 0 0 false ECS 24 24 10.0.0.0");
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
    check_output(&rr, ". OPT 1024 0 0 false ECS 24 24 10::");
}

#[test]
fn rr_opt_cookie_1() {
    let client_cookie = b"\xd5\xa7\xe3\x00\x4d\x79\x05\x1e".to_owned();
    let server_cookie = None;
    let cookie = Cookie::new(client_cookie, server_cookie).unwrap();
    let rr = RR::OPT(OPT {
        requestor_payload_size: 1024,
        dnssec: false,
        version: 0,
        extend_rcode: 0,
        edns_options: vec![EDNSOption::Cookie(cookie)],
    });
    check_output(&rr, ". OPT 1024 0 0 false Cookie d5a7e3004d79051e");
}

#[test]
fn rr_opt_cookie_2() {
    let client_cookie = b"\xd5\xa7\xe3\x00\x4d\x79\x05\x1e".to_owned();
    let server_cookie =
        Some(b"\x01\x00\x00\x00\x5f\xe5\xd6\xb1\x62\xda\x1b\xe3\xbc\x92\x5b\xd6".to_vec());
    let cookie = Cookie::new(client_cookie, server_cookie).unwrap();
    let rr = RR::OPT(OPT {
        requestor_payload_size: 1024,
        dnssec: false,
        version: 0,
        extend_rcode: 0,
        edns_options: vec![EDNSOption::Cookie(cookie)],
    });
    check_output(
        &rr,
        ". OPT 1024 0 0 false Cookie d5a7e3004d79051e 010000005fe5d6b162da1be3bc925bd6",
    );
}

#[test]
fn rr_opt_padding() {
    let padding = Padding(6);
    let rr = RR::OPT(OPT {
        requestor_payload_size: 1024,
        dnssec: false,
        version: 0,
        extend_rcode: 0,
        edns_options: vec![EDNSOption::Padding(padding)],
    });
    check_output(&rr, ". OPT 1024 0 0 false Padding 6");
}

#[test]
fn rr_apl_1() {
    let domain_name = "example.org".parse().unwrap();
    let apitems = Vec::new();
    let rr = RR::APL(APL {
        domain_name,
        ttl: 100,
        apitems,
    });
    check_output(&rr, "example.org. 100 IN APL");
}

#[test]
fn rr_apl_2() {
    let domain_name = "example.org".parse().unwrap();
    let mut apitems = Vec::new();
    let address = Address::Ipv4("10.0.0.0".parse().unwrap());
    let apitem = APItem::new(8, false, address).unwrap();
    apitems.push(apitem);
    let address = Address::Ipv4("20.0.0.0".parse().unwrap());
    let apitem = APItem::new(16, false, address).unwrap();
    apitems.push(apitem);
    let rr = RR::APL(APL {
        domain_name,
        ttl: 100,
        apitems,
    });
    check_output(&rr, "example.org. 100 IN APL 1:10.0.0.0/8 1:20.0.0.0/16");
}

#[test]
fn rr_apl_3() {
    let domain_name = "example.org".parse().unwrap();
    let address = Address::Ipv6("1122:3344::".parse().unwrap());
    let apitem = APItem::new(64, true, address).unwrap();
    let apitems = vec![apitem];
    let rr = RR::APL(APL {
        domain_name,
        ttl: 100,
        apitems,
    });
    check_output(&rr, "example.org. 100 IN APL !2:1122:3344::/64");
}

#[test]
fn rr_dnskey() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let zone_key_flag = true;
    let secure_entry_point_flag = true;
    let algorithm_type = AlgorithmType::Ed25519;
    let public_key = b"\xde\x9f\x0d\x53\xf0\x1d\xe1\x94\x8d\x95\x4c\x7b\xaf\x5b\x25\x13\x54\x19\
    \xc2\x6b\x8f\xc2\xd1\x96\xcd\x5a\x5e\xd9\xfb\x6b\x99\x07"
        .to_vec();
    let rr = RR::DNSKEY(DNSKEY {
        domain_name,
        class,
        ttl: 1234,
        zone_key_flag,
        secure_entry_point_flag,
        algorithm_type,
        public_key,
    });
    check_output(
        &rr,
        "example.org. 1234 IN DNSKEY 257 3 15 de9f0d53f01de1948d954c7baf5b25135419c26b8fc2d196cd5a5ed9fb6b9907",
    );
}

#[test]
fn rr_ds() {
    let domain_name = "dskey.example.org".parse().unwrap();
    let class = Class::CS;
    let key_tag = 5583;
    let algorithm_type = AlgorithmType::Ed448;
    let digest_type = DigestType::Sha256;
    let digest = b"\x89\x04\x8b\x1c\x99\xa2\x8e\x3e\xb5\x42\x5a\x92\xd5\x0b\x77\x8b\x8f\xb4\xa5\
    \xd9\x78\xf0\xf5\xcb\xab\x43\x06\x04\xad\xcf\x73\xba"
        .to_vec();
    let rr = RR::DS(DS {
        domain_name,
        class,
        ttl: 4321,
        key_tag,
        algorithm_type,
        digest_type,
        digest,
    });
    check_output(
        &rr,
        "dskey.example.org. 4321 CS DS 5583 16 2 89048b1c99a28e3eb5425a92d50b778b8fb4a5d978f0f5cba\
        b430604adcf73ba",
    );
}

#[test]
fn rr_caa() {
    let domain_name = "caa.example.org".parse().unwrap();
    let class = Class::IN;
    let flags = 0x80;
    let tag = Tag::try_from("tag".to_string()).unwrap();
    let value = b"VALUE".to_vec();
    let rr = RR::CAA(CAA {
        domain_name,
        class,
        ttl: 1234,
        flags,
        tag,
        value,
    });
    check_output(&rr, "caa.example.org. 1234 IN CAA 128 tag 56414c5545");
}

#[test]
fn rr_svcb_alias() {
    // given
    let domain_name = "_8443._foo.api.example.com".parse().unwrap();
    let target_name = "svc4.example.net.".parse().unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 0,
        target_name,
        parameters: BTreeSet::default(),
        https: false,
    };

    // when
    let rr = RR::SVCB(service_binding);

    // then
    check_output(
        &rr,
        "_8443._foo.api.example.com. 7200 IN SVCB 0 svc4.example.net.",
    );
}

#[test]
fn rr_svcb_service() {
    // given
    let domain_name = "svc4.example.net.".parse().unwrap();
    let target_name = "svc4.example.net.".parse().unwrap();
    let application_layer_protocol_negotiation = ServiceParameter::ALPN {
        alpn_ids: vec!["bar".to_string()],
    };
    let port = ServiceParameter::PORT { port: 8004 };

    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 3,
        target_name,
        parameters: vec![application_layer_protocol_negotiation, port]
            .into_iter()
            .collect::<BTreeSet<ServiceParameter>>(),
        https: false,
    };

    // when
    let rr = RR::SVCB(service_binding);

    // then
    check_output(
        &rr,
        "svc4.example.net. 7200 IN SVCB 3 svc4.example.net. alpn=bar port=8004",
    );
}

/// Test alias mode for default `https://` and `http://` on ports 443 and 80 respectively.
///
/// https://indico.dns-oarc.net/event/37/contributions/813/attachments/781/1365/SVCB_HTTPS_%20DNS-OARC%202021%20%281%29.pdf
#[test]
fn rr_https_alias_default() {
    // given
    let domain_name = "example.com".parse().unwrap();
    let target_name = "svc.example.net".parse().unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 0, // alias mode
        target_name,
        parameters: BTreeSet::default(),
        https: true,
    };

    // when
    let rr = RR::HTTPS(service_binding);

    // then
    check_output(&rr, "example.com. 7200 IN HTTPS 0 svc.example.net.");
}

/// Test alias mode for default `https://` on an alternative port.
///
/// https://indico.dns-oarc.net/event/37/contributions/813/attachments/781/1365/SVCB_HTTPS_%20DNS-OARC%202021%20%281%29.pdf
#[test]
fn rr_https_alias_alternative_port() {
    // given
    let domain_name = "_8443._https.example.com".parse().unwrap();
    let target_name = "svc.example.net".parse().unwrap();
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 0, // alias mode
        target_name,
        parameters: BTreeSet::default(),
        https: true,
    };

    // when
    let rr = RR::HTTPS(service_binding);

    // then
    check_output(
        &rr,
        "_8443._https.example.com. 7200 IN HTTPS 0 svc.example.net.",
    );
}

/// Example from:
/// https://indico.dns-oarc.net/event/37/contributions/813/attachments/781/1365/SVCB_HTTPS_%20DNS-OARC%202021%20%281%29.pdf
#[test]
fn rr_https_quic_to_udp() {
    // given
    let domain_name = "svc.example.net".parse().unwrap();
    let target_name = "svc3.example.net".parse().unwrap();
    let application_layer_protocol_negotiation = ServiceParameter::ALPN {
        alpn_ids: vec!["h3".to_string()],
    };
    let port = ServiceParameter::PORT { port: 8003 };
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 2,
        target_name,
        parameters: vec![application_layer_protocol_negotiation, port]
            .into_iter()
            .collect::<BTreeSet<ServiceParameter>>(),
        https: true,
    };

    // when
    let rr = RR::HTTPS(service_binding);

    // then
    check_output(
        &rr,
        "svc.example.net. 7200 IN HTTPS 2 svc3.example.net. alpn=h3 port=8003",
    );
}

/// Example from:
/// https://indico.dns-oarc.net/event/37/contributions/813/attachments/781/1365/SVCB_HTTPS_%20DNS-OARC%202021%20%281%29.pdf
#[test]
fn rr_https_h2_to_tcp() {
    // given
    let domain_name = "svc.example.net".parse().unwrap();
    let target_name = "svc2.example.net".parse().unwrap();
    let application_layer_protocol_negotiation = ServiceParameter::ALPN {
        alpn_ids: vec!["h2".to_string()],
    };
    let port = ServiceParameter::PORT { port: 8002 };
    let service_binding = ServiceBinding {
        name: domain_name,
        ttl: 7200,
        priority: 3,
        target_name,
        parameters: vec![application_layer_protocol_negotiation, port]
            .into_iter()
            .collect::<BTreeSet<ServiceParameter>>(),
        https: true,
    };

    // when
    let rr = RR::HTTPS(service_binding);

    // then
    check_output(
        &rr,
        "svc.example.net. 7200 IN HTTPS 3 svc2.example.net. alpn=h2 port=8002",
    );
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
fn q_class_none() {
    let q_type = QClass::NONE;
    check_output(&q_type, "NONE");
}

#[test]
fn question() {
    let domain_name = "example.org.".parse().unwrap();
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
        let domain_name = "cname.example.org.".parse().unwrap();
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
        let domain_name = "cname.example.org.".parse().unwrap();
        let class = Class::IN;
        let ttl = 3600;
        let c_name = "example.org.".parse().unwrap();
        let c_name = CNAME {
            domain_name,
            ttl,
            class,
            c_name,
        };
        vec![RR::CNAME(c_name)]
    };
    let authorities = {
        let domain_name = "ns1.example.org.".parse().unwrap();
        let class = Class::IN;
        let ttl = 3600;
        let ns_d_name = "example.org.".parse().unwrap();
        let ns = NS {
            domain_name,
            ttl,
            class,
            ns_d_name,
        };
        vec![RR::NS(ns)]
    };
    let additionals = {
        let domain_name = "example.org.".parse().unwrap();
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

#[test]
fn rr_opt_extended_dns_errors() {
    let extended_dns_errors = ExtendedDNSErrors {
        info_code: ExtendedDNSErrorCodes::UnsupportedDNSKEYAlgorithm,
        extra_text: ExtendedDNSErrorExtraText::try_from("TEST").unwrap(),
    };
    let rr = RR::OPT(OPT {
        requestor_payload_size: 1024,
        dnssec: false,
        version: 0,
        extend_rcode: 0,
        edns_options: vec![EDNSOption::ExtendedDNSErrors(extended_dns_errors)],
    });
    check_output(
        &rr,
        ". OPT 1024 0 0 false Extended DNS Errors UnsupportedDNSKEYAlgorithm TEST",
    );
}
