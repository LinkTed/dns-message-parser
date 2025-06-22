use crate::encode::Encoder;
use crate::rr::edns::{EDNSOptionCode, ExtendedDNSErrors};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_edns_extended_dns_errors(
        &mut self,
        extended_dns_errors: &ExtendedDNSErrors,
    ) -> EncodeResult<()> {
        self.rr_edns_option_code(&EDNSOptionCode::ExtendedDnsError);
        let length_index = self.create_length_index();
        self.u16(extended_dns_errors.info_code as u16);
        self.string(extended_dns_errors.extra_text.as_ref())?;
        self.set_length_index(length_index)
    }
}
