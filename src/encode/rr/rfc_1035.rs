use crate::encode::Encoder;
use crate::rr::{Class, Type, A, HINFO, SOA, TXT, WKS};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_a(&mut self, a: &A) -> EncodeResult<()> {
        self.domain_name(&a.domain_name)?;
        self.rr_type(&Type::A);
        self.rr_class(&Class::IN);
        self.u32(a.ttl);
        let length_index = self.create_length_index();
        self.ipv4_addr(&a.ipv4_addr);
        self.set_length_index(length_index)
    }

    impl_encode_rr_domain_name!(NS, ns_d_name, rr_ns);

    impl_encode_rr_domain_name!(MD, mad_name, rr_md);

    impl_encode_rr_domain_name!(MF, mad_name, rr_mf);

    impl_encode_rr_domain_name!(CNAME, c_name, rr_cname);

    pub(super) fn rr_soa(&mut self, soa: &SOA) -> EncodeResult<()> {
        self.domain_name(&soa.domain_name)?;
        self.rr_type(&Type::SOA);
        self.rr_class(&soa.class);
        self.u32(soa.ttl);
        let length_index = self.create_length_index();
        self.domain_name(&soa.m_name)?;
        self.domain_name(&soa.r_name)?;
        self.u32(soa.serial);
        self.u32(soa.refresh);
        self.u32(soa.retry);
        self.u32(soa.expire);
        self.u32(soa.min_ttl);
        self.set_length_index(length_index)
    }

    impl_encode_rr_domain_name!(MB, mad_name, rr_mb);

    impl_encode_rr_domain_name!(MG, mgm_name, rr_mg);

    impl_encode_rr_domain_name!(MR, new_name, rr_mr);

    impl_encode_rr_vec!(NULL, data, rr_null);

    pub(super) fn rr_wks(&mut self, wks: &WKS) -> EncodeResult<()> {
        self.domain_name(&wks.domain_name)?;
        self.rr_type(&Type::WKS);
        self.rr_class(&Class::IN);
        self.u32(wks.ttl);
        let length_index = self.create_length_index();
        self.ipv4_addr(&wks.ipv4_addr);
        self.u8(wks.protocol);
        self.vec(&wks.bit_map);
        self.set_length_index(length_index)
    }

    impl_encode_rr_domain_name!(PTR, ptr_d_name, rr_ptr);

    pub(super) fn rr_hinfo(&mut self, hinfo: &HINFO) -> EncodeResult<()> {
        self.domain_name(&hinfo.domain_name)?;
        self.rr_type(&Type::HINFO);
        self.rr_class(&hinfo.class);
        self.u32(hinfo.ttl);
        let length_index = self.create_length_index();
        self.string(&hinfo.cpu)?;
        self.string(&hinfo.os)?;
        self.set_length_index(length_index)
    }

    impl_encode_rr_domain_name_domain_name!(MINFO, r_mail_bx, e_mail_bx, rr_minfo);

    impl_encode_rr_u16_domain_name!(MX, preference, exchange, rr_mx);

    pub(super) fn rr_txt(&mut self, txt: &TXT) -> EncodeResult<()> {
        self.domain_name(&txt.domain_name)?;
        self.rr_type(&Type::TXT);
        self.rr_class(&txt.class);
        self.u32(txt.ttl);
        let length_index = self.create_length_index();
        for string in txt.strings.iter() {
            self.string(string)?;
        }
        self.set_length_index(length_index)
    }
}

impl_encode_rr!(A, rr_a);

impl_encode_rr!(NS, rr_ns);

impl_encode_rr!(MD, rr_md);

impl_encode_rr!(MF, rr_mf);

impl_encode_rr!(CNAME, rr_cname);

impl_encode_rr!(SOA, rr_soa);

impl_encode_rr!(MB, rr_mb);

impl_encode_rr!(MG, rr_mg);

impl_encode_rr!(MR, rr_mr);

impl_encode_rr!(NULL, rr_null);

impl_encode_rr!(WKS, rr_wks);

impl_encode_rr!(PTR, rr_ptr);

impl_encode_rr!(HINFO, rr_hinfo);

impl_encode_rr!(MINFO, rr_minfo);

impl_encode_rr!(MX, rr_mx);

impl_encode_rr!(TXT, rr_txt);
