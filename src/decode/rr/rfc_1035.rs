use super::Header;
use crate::decode::Decoder;
use crate::rr::{Class, A, HINFO, SOA, WKS};
use crate::{DecodeError, DecodeResult};

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_a(&mut self, header: Header) -> DecodeResult<A> {
        match header.get_class()? {
            Class::IN => {
                let ipv4_addr = self.ipv4_addr()?;
                let a = A {
                    domain_name: header.domain_name,
                    ttl: header.ttl,
                    ipv4_addr,
                };
                Ok(a)
            }
            class => Err(DecodeError::AClass(class)),
        }
    }

    impl_decode_rr_domain_name!(NS, ns_d_name, rr_ns);

    impl_decode_rr_domain_name!(MD, mad_name, rr_md);

    impl_decode_rr_domain_name!(MF, mad_name, rr_mf);

    impl_decode_rr_domain_name!(CNAME, c_name, rr_cname);

    pub(super) fn rr_soa(&mut self, header: Header) -> DecodeResult<SOA> {
        let class = header.get_class()?;
        let m_name = self.domain_name()?;
        let r_name = self.domain_name()?;
        let serial = self.u32()?;
        let refresh = self.u32()?;
        let retry = self.u32()?;
        let expire = self.u32()?;
        let min_ttl = self.u32()?;

        let soa = SOA {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            m_name,
            r_name,
            serial,
            refresh,
            retry,
            expire,
            min_ttl,
        };

        Ok(soa)
    }

    impl_decode_rr_domain_name!(MB, mad_name, rr_mb);

    impl_decode_rr_domain_name!(MG, mgm_name, rr_mg);

    impl_decode_rr_domain_name!(MR, new_name, rr_mr);

    impl_decode_rr_vec!(NULL, data, rr_null);

    pub(super) fn rr_wks(&mut self, header: Header) -> DecodeResult<WKS> {
        match header.get_class()? {
            Class::IN => {
                let ipv4_addr = self.ipv4_addr()?;
                let protocol = self.u8()?;
                let bit_map = self.vec()?;
                let wks = WKS {
                    domain_name: header.domain_name,
                    ttl: header.ttl,
                    ipv4_addr,
                    protocol,
                    bit_map,
                };
                Ok(wks)
            }
            class => Err(DecodeError::WKSClass(class)),
        }
    }

    impl_decode_rr_domain_name!(PTR, ptr_d_name, rr_ptr);

    pub(super) fn rr_hinfo(&mut self, header: Header) -> DecodeResult<HINFO> {
        let class = header.get_class()?;
        let cpu = self.string()?;
        let os = self.string()?;
        let hinfo = HINFO {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            cpu,
            os,
        };
        Ok(hinfo)
    }

    impl_decode_rr_domain_name_domain_name!(MINFO, r_mail_bx, e_mail_bx, rr_minfo);

    impl_decode_rr_u16_domain_name!(MX, preference, exchange, rr_mx);

    impl_decode_rr_string!(TXT, string, rr_txt);
}
