use dns_message_parser::rr::{
    AFSDBSubtype, Class, ISDNAddress, PSDNAddress, SSHFPAlgorithm, SSHFPType, ServiceBinding, A,
    AAAA, AFSDB, APL, CNAME, DNAME, EID, EUI48, EUI64, GPOS, HINFO, ISDN, KX, L32, L64, LP, MB, MD,
    MF, MG, MINFO, MR, MX, NID, NIMLOC, NS, OPT, PTR, PX, RP, RR, RT, SA, SOA, SRV, SSHFP, TXT,
    URI, X25,
};
use dns_message_parser::DomainName;
use std::collections::BTreeSet;
use std::convert::{TryFrom, TryInto};

#[test]
fn a() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let ipv4_addr = "10.0.0.1".parse().unwrap();
    let rr = RR::A(A {
        domain_name,
        ttl: 100,
        ipv4_addr,
    });
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn ns() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let ns_d_name = DomainName::try_from("ns1.example.org").unwrap();
    let rr = RR::NS(NS {
        domain_name,
        ttl: 100,
        class,
        ns_d_name,
    });
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn cname() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let c_name = DomainName::try_from("example.org").unwrap();
    let rr = RR::CNAME(CNAME {
        domain_name,
        ttl: 100,
        class,
        c_name,
    });
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn soa() {
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
    assert_eq!(rr.get_class(), Some(Class::CH));
}

#[test]
fn mb() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let mad_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MB(MB {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn md() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let mad_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MD(MD {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn mf() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let mad_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MF(MF {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn mg() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let mgm_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MG(MG {
        domain_name,
        ttl: 100,
        class,
        mgm_name,
    });
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn mr() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let new_name = DomainName::try_from("mail.example.org").unwrap();
    let rr = RR::MR(MR {
        domain_name,
        ttl: 100,
        class,
        new_name,
    });
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn ptr() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let ptr_d_name = DomainName::try_from("example.org").unwrap();
    let rr = RR::PTR(PTR {
        domain_name,
        ttl: 100,
        class,
        ptr_d_name,
    });
    assert_eq!(rr.get_class(), Some(Class::CH));
}

#[test]
fn hinfo() {
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
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn minfo() {
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
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn mx() {
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
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn txt() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let strings = vec![String::from("Text")].try_into().unwrap();
    let rr = RR::TXT(TXT {
        domain_name,
        ttl: 100,
        class,
        strings,
    });
    assert_eq!(rr.get_class(), Some(Class::CH));
}

#[test]
fn rp() {
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
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn afsdb() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let subtype = AFSDBSubtype::VolumeLocationServer;
    let hostname = DomainName::try_from("afsdb.example.org").unwrap();
    let rr = RR::AFSDB(AFSDB {
        domain_name,
        ttl: 100,
        class,
        subtype,
        hostname,
    });
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn x25() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::IN;
    let psdn_address = PSDNAddress::try_from(String::from("311061700956")).unwrap();
    let rr = RR::X25(X25 {
        domain_name,
        ttl: 100,
        class,
        psdn_address,
    });
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn isdn_1() {
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
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn isdn_2() {
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
    assert_eq!(rr.get_class(), Some(Class::CH));
}

#[test]
fn rt() {
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
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn px() {
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
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn gpos() {
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
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn aaaa() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let ipv6_addr = "::1".parse().unwrap();
    let rr = RR::AAAA(AAAA {
        domain_name,
        ttl: 100,
        ipv6_addr,
    });
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn eid() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let data = Vec::from(&b"\xe3\x2c\x6f\x78\x16\x3a\x93\x48"[..]);
    let rr = RR::EID(EID {
        domain_name,
        ttl: 100,
        class,
        data,
    });
    assert_eq!(rr.get_class(), Some(Class::CH));
}

#[test]
fn nimloc() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::HS;
    let data = Vec::from(&b"\x32\x25\x1a\x03\x00\x67"[..]);
    let rr = RR::NIMLOC(NIMLOC {
        domain_name,
        ttl: 100,
        class,
        data,
    });
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn srv() {
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
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn kx() {
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
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn dname() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let target = DomainName::try_from("dname.example.org").unwrap();
    let rr = RR::DNAME(DNAME {
        domain_name,
        ttl: 100,
        class,
        target,
    });
    assert_eq!(rr.get_class(), Some(Class::CH));
}

#[test]
fn sshfp() {
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
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn nid() {
    let domain_name = DomainName::try_from("example.org").unwrap();
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
    assert_eq!(rr.get_class(), Some(Class::CH));
}

#[test]
fn l32() {
    let domain_name = DomainName::try_from("example.org").unwrap();
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
    assert_eq!(rr.get_class(), Some(Class::HS));
}

#[test]
fn l64() {
    let domain_name = DomainName::try_from("example.org").unwrap();
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
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn lp() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let preference = 200;
    let fqdn = DomainName::try_from("l64-subnet.example.org.").unwrap();
    let rr = RR::LP(LP {
        domain_name,
        ttl: 100,
        class,
        preference,
        fqdn,
    });
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn eui48() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CS;
    let eui_48 = b"\x00\x11\x22\x33\x44\x55".to_owned();
    let rr = RR::EUI48(EUI48 {
        domain_name,
        ttl: 100,
        class,
        eui_48,
    });
    assert_eq!(rr.get_class(), Some(Class::CS));
}

#[test]
fn eui64() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let class = Class::CH;
    let eui_64 = b"\x00\x11\x22\x33\x44\x55\x66\x77".to_owned();
    let rr = RR::EUI64(EUI64 {
        domain_name,
        ttl: 100,
        class,
        eui_64,
    });
    assert_eq!(rr.get_class(), Some(Class::CH));
}

#[test]
fn uri() {
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
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn opt() {
    let rr = RR::OPT(OPT {
        requestor_payload_size: 1024,
        dnssec: false,
        version: 0,
        extend_rcode: 0,
        edns_options: Vec::new(),
    });
    assert_eq!(rr.get_class(), None);
}

#[test]
fn rr_apl() {
    let domain_name = DomainName::try_from("example.org").unwrap();
    let apitems = Vec::new();
    let rr = RR::APL(APL {
        domain_name,
        ttl: 300,
        apitems,
    });
    assert_eq!(rr.get_class(), Some(Class::IN));
}

#[test]
fn rr_svcb() {
    // given
    let domain_name = DomainName::try_from("www.example.com").unwrap();
    let target_name = DomainName::try_from("service.example.com").unwrap();
    let rr = RR::SVCB(ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: BTreeSet::default(),
        https: false,
    });

    // when
    let class = rr.get_class();

    // then
    assert_eq!(class, Some(Class::IN));
}

#[test]
fn rr_https() {
    // given
    let domain_name = DomainName::try_from("www.example.com").unwrap();
    let target_name = DomainName::try_from("service.example.com").unwrap();
    let rr = RR::HTTPS(ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: BTreeSet::default(),
        https: true,
    });

    // when
    let class = rr.get_class();

    // then
    assert_eq!(class, Some(Class::IN));
}
