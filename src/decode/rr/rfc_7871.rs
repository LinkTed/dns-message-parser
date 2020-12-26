use crate::decode::Decoder;
use crate::rr::ECS;
use crate::DecodeResult;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_edns_ecs(&mut self) -> DecodeResult<ECS> {
        let address_family_number = self.rr_address_family_number()?;
        let source_prefix_length = self.u8()?;
        let scope_prefix_length = self.u8()?;
        let address = self.rr_address(address_family_number)?;
        let ecs = ECS::new(source_prefix_length, scope_prefix_length, address)?;
        Ok(ecs)
    }
}
