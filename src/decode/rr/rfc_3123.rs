use super::Header;
use crate::decode::Decoder;
use crate::rr::{APItem, Class, APL, APL_NEGATION_MASK};
use crate::{DecodeError, DecodeResult};

const ADDRESS_LENGTH_MASK: u8 = 0b0111_1111;

impl<'a, 'b: 'a> Decoder<'b, 'b> {
    pub(super) fn rr_apl_apitem(&'a mut self) -> DecodeResult<APItem> {
        let address_family_number = self.rr_address_family_number()?;
        let prefix = self.u8()?;
        let buffer = self.u8()?;
        let negation = (buffer & APL_NEGATION_MASK) == APL_NEGATION_MASK;
        let address_length = buffer & ADDRESS_LENGTH_MASK;
        let mut address_data = self.sub(address_length as u16)?;
        let address = address_data.rr_address(address_family_number)?;
        address_data.finished()?;
        let apitem = APItem::new(prefix, negation, address)?;
        Ok(apitem)
    }

    pub(super) fn rr_apl(&'a mut self, header: Header) -> DecodeResult<APL> {
        match header.get_class()? {
            Class::IN => {
                let mut apitems = Vec::new();
                while !self.is_finished()? {
                    apitems.push(self.rr_apl_apitem()?);
                }
                let apl = APL {
                    domain_name: header.domain_name,
                    ttl: header.ttl,
                    apitems,
                };
                Ok(apl)
            }
            class => Err(DecodeError::APLClass(class)),
        }
    }
}
