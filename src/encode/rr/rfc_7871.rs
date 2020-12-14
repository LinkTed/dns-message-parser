use crate::encode::Encoder;
use crate::rr::{Address, AddressNumber, EDNSOptionCode, ECS};
use crate::EncodeResult;
use std::net::{Ipv4Addr, Ipv6Addr};

impl Encoder {
    #[inline]
    fn rr_edns_ecs_address_number(&mut self, address_number: &AddressNumber) {
        self.u16(address_number.clone() as u16);
    }

    fn rr_edns_ecs_address_ipv4(&mut self, ipv4_addr: &Ipv4Addr, mut prefix_length: u8) {
        let ipv4_addr = ipv4_addr.octets();
        for b in &ipv4_addr {
            self.u8(*b);
            if prefix_length < 8 {
                break;
            } else {
                prefix_length -= 8;
            }
        }
    }

    fn rr_edns_ecs_address_ipv6(&mut self, ipv6_addr: &Ipv6Addr, mut prefix_length: u8) {
        let ipv6_addr = ipv6_addr.octets();
        for b in &ipv6_addr {
            self.u8(*b);
            if prefix_length < 8 {
                break;
            } else {
                prefix_length -= 8;
            }
        }
    }

    fn rr_edns_ecs_address(&mut self, address: &Address, prefix_length: u8) {
        match address {
            Address::Ipv4(ipv4_addr) => self.rr_edns_ecs_address_ipv4(ipv4_addr, prefix_length),
            Address::Ipv6(ipv6_addr) => self.rr_edns_ecs_address_ipv6(ipv6_addr, prefix_length),
        }
    }

    pub(super) fn rr_edns_ecs(&mut self, ecs: &ECS) -> EncodeResult<()> {
        self.rr_edns_option_code(&EDNSOptionCode::ECS);
        let length_index = self.create_length_index();
        let address = ecs.get_address();
        self.rr_edns_ecs_address_number(&address.get_address_number());
        self.u8(ecs.get_source_prefix_length());
        self.u8(ecs.get_scope_prefix_length());
        self.rr_edns_ecs_address(address, ecs.get_prefix_length());
        self.set_length_index(length_index)
    }
}
