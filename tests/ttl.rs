use dns_message_parser::rr::{
    AFSDBSubtype, Class, ISDNAddress, PSDNAddress, SSHFPAlgorithm, SSHFPType, ServiceBinding, A,
    AAAA, AFSDB, APL, CNAME, DNAME, EID, EUI48, EUI64, GPOS, HINFO, ISDN, KX, L32, L64, LP, MB, MD,
    MF, MG, MINFO, MR, MX, NID, NIMLOC, NS, OPT, PTR, PX, RP, RR, RT, SA, SOA, SRV, SSHFP, TXT,
    URI, X25,
};
use std::{
    collections::BTreeSet,
    convert::{TryFrom, TryInto},
};

#[test]
fn a() {
    let domain_name = "example.org".parse().unwrap();
    let ipv4_addr = "10.0.0.1".parse().unwrap();
    let rr = RR::A(A {
        domain_name,
        ttl: 100,
        ipv4_addr,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn ns() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let ns_d_name = "ns1.example.org".parse().unwrap();
    let rr = RR::NS(NS {
        domain_name,
        ttl: 100,
        class,
        ns_d_name,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn cname() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let c_name = "example.org".parse().unwrap();
    let rr = RR::CNAME(CNAME {
        domain_name,
        ttl: 100,
        class,
        c_name,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn soa() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn mb() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let mad_name = "mail.example.org".parse().unwrap();
    let rr = RR::MB(MB {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn md() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let mad_name = "mail.example.org".parse().unwrap();
    let rr = RR::MD(MD {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn mf() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let mad_name = "mail.example.org".parse().unwrap();
    let rr = RR::MF(MF {
        domain_name,
        ttl: 100,
        class,
        mad_name,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn mg() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let mgm_name = "mail.example.org".parse().unwrap();
    let rr = RR::MG(MG {
        domain_name,
        ttl: 100,
        class,
        mgm_name,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn mr() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let new_name = "mail.example.org".parse().unwrap();
    let rr = RR::MR(MR {
        domain_name,
        ttl: 100,
        class,
        new_name,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn ptr() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let ptr_d_name = "example.org".parse().unwrap();
    let rr = RR::PTR(PTR {
        domain_name,
        ttl: 100,
        class,
        ptr_d_name,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn hinfo() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn minfo() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn mx() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn txt() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let strings = vec![String::from("Text")].try_into().unwrap();
    let rr = RR::TXT(TXT {
        domain_name,
        ttl: 100,
        class,
        strings,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn rp() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn afsdb() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let subtype = AFSDBSubtype::VolumeLocationServer;
    let hostname = "afsdb.example.org".parse().unwrap();
    let rr = RR::AFSDB(AFSDB {
        domain_name,
        ttl: 100,
        class,
        subtype,
        hostname,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn x25() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::IN;
    let psdn_address = PSDNAddress::try_from(String::from("311061700956")).unwrap();
    let rr = RR::X25(X25 {
        domain_name,
        ttl: 100,
        class,
        psdn_address,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn isdn_1() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn isdn_2() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn rt() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn px() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn gpos() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn aaaa() {
    let domain_name = "example.org".parse().unwrap();
    let ipv6_addr = "::1".parse().unwrap();
    let rr = RR::AAAA(AAAA {
        domain_name,
        ttl: 100,
        ipv6_addr,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn eid() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let data = Vec::from(&b"\xe3\x2c\x6f\x78\x16\x3a\x93\x48"[..]);
    let rr = RR::EID(EID {
        domain_name,
        ttl: 100,
        class,
        data,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn nimloc() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::HS;
    let data = Vec::from(&b"\x32\x25\x1a\x03\x00\x67"[..]);
    let rr = RR::NIMLOC(NIMLOC {
        domain_name,
        ttl: 100,
        class,
        data,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn srv() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn kx() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn dname() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let target = "dname.example.org".parse().unwrap();
    let rr = RR::DNAME(DNAME {
        domain_name,
        ttl: 100,
        class,
        target,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn sshfp() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn nid() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn l32() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn l64() {
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
    assert_eq!(rr.get_ttl(), Some(200));
}

#[test]
fn lp() {
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
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn eui48() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CS;
    let eui_48 = b"\x00\x11\x22\x33\x44\x55".to_owned();
    let rr = RR::EUI48(EUI48 {
        domain_name,
        ttl: 100,
        class,
        eui_48,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn eui64() {
    let domain_name = "example.org".parse().unwrap();
    let class = Class::CH;
    let eui_64 = b"\x00\x11\x22\x33\x44\x55\x66\x77".to_owned();
    let rr = RR::EUI64(EUI64 {
        domain_name,
        ttl: 100,
        class,
        eui_64,
    });
    assert_eq!(rr.get_ttl(), Some(100));
}

#[test]
fn uri() {
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
    assert_eq!(rr.get_ttl(), Some(100));
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
    assert_eq!(rr.get_ttl(), None);
}

#[test]
fn rr_apl() {
    let domain_name = "example.org".parse().unwrap();
    let apitems = Vec::new();
    let rr = RR::APL(APL {
        domain_name,
        ttl: 300,
        apitems,
    });
    assert_eq!(rr.get_ttl(), Some(300));
}

#[test]
fn rr_svcb() {
    // given
    let domain_name = "www.example.com".parse().unwrap();
    let target_name = "service.example.com".parse().unwrap();
    let rr = RR::SVCB(ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: BTreeSet::default(),
        https: false,
    });

    // when
    let ttl = rr.get_ttl();

    // then
    assert_eq!(ttl, Some(300));
}

#[test]
fn rr_https() {
    // given
    let domain_name = "www.example.com".parse().unwrap();
    let target_name = "service.example.com".parse().unwrap();
    let rr = RR::HTTPS(ServiceBinding {
        name: domain_name,
        ttl: 300,
        priority: 1,
        target_name,
        parameters: BTreeSet::default(),
        https: true,
    });

    // when
    let ttl = rr.get_ttl();

    // then
    assert_eq!(ttl, Some(300));
}
