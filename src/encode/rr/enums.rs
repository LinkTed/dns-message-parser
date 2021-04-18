use crate::encode::Encoder;
use crate::rr::{Class, Type, RR};
use crate::EncodeResult;

impl Encoder {
    #[inline]
    pub(super) fn rr_type(&mut self, type_: &Type) {
        self.u16(type_.clone() as u16);
    }

    #[inline]
    pub(super) fn rr_class(&mut self, class: &Class) {
        self.u16(class.clone() as u16);
    }

    pub(crate) fn rr(&mut self, rr: &RR) -> EncodeResult<()> {
        match rr {
            RR::A(a) => self.rr_a(a),
            RR::NS(ns) => self.rr_ns(ns),
            RR::MD(md) => self.rr_md(md),
            RR::MF(mf) => self.rr_mf(mf),
            RR::CNAME(cname) => self.rr_cname(cname),
            RR::SOA(soa) => self.rr_soa(soa),
            RR::MB(mb) => self.rr_mb(mb),
            RR::MG(mg) => self.rr_mg(mg),
            RR::MR(mr) => self.rr_mr(mr),
            RR::NULL(null) => self.rr_null(null),
            RR::WKS(wks) => self.rr_wks(wks),
            RR::PTR(ptr) => self.rr_ptr(ptr),
            RR::HINFO(hinfo) => self.rr_hinfo(hinfo),
            RR::MINFO(minfo) => self.rr_minfo(minfo),
            RR::MX(mx) => self.rr_mx(mx),
            RR::TXT(txt) => self.rr_txt(txt),
            RR::RP(rp) => self.rr_rp(rp),
            RR::AFSDB(afsdb) => self.rr_afsdb(afsdb),
            RR::X25(x25) => self.rr_x25(x25),
            RR::ISDN(isdn) => self.rr_isdn(isdn),
            RR::RT(rt) => self.rr_rt(rt),
            RR::NSAP(nsap) => self.rr_nsap(nsap),
            RR::GPOS(gpos) => self.rr_gpos(gpos),
            RR::LOC(loc) => self.rr_loc(loc),
            RR::PX(px) => self.rr_px(px),
            RR::KX(kx) => self.rr_kx(kx),
            RR::SRV(srv) => self.rr_srv(srv),
            RR::AAAA(aaaa) => self.rr_aaaa(aaaa),
            RR::SSHFP(sshfp) => self.rr_sshfp(sshfp),
            RR::DNAME(dname) => self.rr_dname(dname),
            RR::OPT(opt) => self.rr_opt(opt),
            RR::APL(apl) => self.rr_apl(apl),
            RR::NID(n_id) => self.rr_nid(n_id),
            RR::L32(l_32) => self.rr_l32(l_32),
            RR::L64(l_64) => self.rr_l64(l_64),
            RR::LP(lp) => self.rr_lp(lp),
            RR::EUI48(eui_48) => self.rr_eui48(eui_48),
            RR::EUI64(eui_64) => self.rr_eui64(eui_64),
            RR::URI(uri) => self.rr_uri(uri),
            RR::EID(eid) => self.rr_eid(eid),
            RR::NIMLOC(nimloc) => self.rr_nimloc(nimloc),
            RR::DNSKEY(dnskey) => self.rr_dnskey(dnskey),
            RR::DS(ds) => self.rr_ds(ds),
            RR::CAA(caa) => self.rr_caa(caa),
            RR::SVCB(svcb) => self.rr_service_binding(svcb),
            RR::HTTPS(https) => self.rr_service_binding(https),
        }
    }
}

impl_encode_without_result!(Type, rr_type);

impl_encode_without_result!(Class, rr_class);

impl_encode!(RR, rr);
