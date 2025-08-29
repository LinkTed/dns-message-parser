use crate::decode::Decoder;
use crate::rr::edns::{ExtendedDNSErrorCodes, ExtendedDNSErrorExtraText, ExtendedDNSErrors};
use crate::{DecodeError, DecodeResult};
use std::convert::TryFrom;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn rr_edns_extended_dns_error_codes(&mut self) -> DecodeResult<ExtendedDNSErrorCodes> {
        let buffer = self.u16()?;
        match ExtendedDNSErrorCodes::try_from(buffer) {
            Ok(edns_extended_dns_errors_codes) => Ok(edns_extended_dns_errors_codes),
            Err(buffer) => Err(DecodeError::ExtendedDNSErrorCodes(buffer)),
        }
    }

    fn rr_edns_extended_dns_errors_extra_text(
        &mut self,
    ) -> DecodeResult<ExtendedDNSErrorExtraText> {
        let extended_dns_errors_extra_text =
            ExtendedDNSErrorExtraText::try_from(self.string(self.remaining()?)?)?;
        Ok(extended_dns_errors_extra_text)
    }

    pub(super) fn rr_edns_extended_dns_errors(&mut self) -> DecodeResult<ExtendedDNSErrors> {
        println!("AA");
        let info_code = self.rr_edns_extended_dns_error_codes()?;
        println!("AA");
        let extra_text = self.rr_edns_extended_dns_errors_extra_text()?;
        println!("AA {0}", extra_text.as_ref().is_empty());
        Ok(ExtendedDNSErrors {
            info_code,
            extra_text,
        })
    }
}
