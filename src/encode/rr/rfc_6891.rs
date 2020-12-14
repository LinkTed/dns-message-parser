use crate::encode::Encoder;
use crate::rr::{EDNSOption, EDNSOptionCode, Type, OPT};
use crate::{DomainName, EncodeResult};

fn rr_opt_ttl(extend_rcode: u8, version: u8, dnssec: bool) -> u32 {
    let mut result = 0;
    result |= (extend_rcode as u32) << 24;
    result |= (version as u32) << 16;
    result |= (dnssec as u32) << 8;
    result
}

impl Encoder {
    #[inline]
    pub(super) fn rr_edns_option_code(&mut self, edns_option_code: &EDNSOptionCode) {
        self.u16(edns_option_code.clone() as u16);
    }

    fn rr_edns_option(&mut self, edns_option: &EDNSOption) -> EncodeResult<()> {
        match edns_option {
            EDNSOption::ECS(ecs) => self.rr_edns_ecs(ecs),
            EDNSOption::Cookie(cookie) => self.rr_edns_cookie(cookie),
        }
    }

    pub(super) fn rr_opt(&mut self, opt: &OPT) -> EncodeResult<()> {
        self.domain_name(&DomainName::default())?;
        self.rr_type(&Type::OPT);
        self.u16(opt.requestor_payload_size);
        self.u32(rr_opt_ttl(opt.extend_rcode, opt.version, opt.dnssec));
        let length_index = self.create_length_index();
        for ends_option in opt.edns_options.iter() {
            self.rr_edns_option(ends_option)?;
        }
        self.set_length_index(length_index)
    }
}
