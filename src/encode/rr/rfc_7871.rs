use crate::encode::Encoder;
use crate::rr::{EDNSOptionCode, ECS};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_edns_ecs(&mut self, ecs: &ECS) -> EncodeResult<()> {
        self.rr_edns_option_code(&EDNSOptionCode::ECS);
        let length_index = self.create_length_index();
        let address = ecs.get_address();
        self.rr_address_family_number(&address.get_address_family_number());
        self.u8(ecs.get_source_prefix_length());
        self.u8(ecs.get_scope_prefix_length());
        self.rr_address_with_prefix(address, ecs.get_prefix_length());
        self.set_length_index(length_index)
    }
}
