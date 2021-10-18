use crate::encode::Encoder;
use crate::rr::{Address, AddressFamilyNumber};
use std::net::{Ipv4Addr, Ipv6Addr};

impl Encoder {
    #[inline]
    pub(super) fn rr_address_family_number(&mut self, address_number: &AddressFamilyNumber) {
        self.u16(*address_number as u16);
    }

    fn rr_address_ipv4(&mut self, ipv4_addr: &Ipv4Addr, mut prefix_length: u8) {
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

    fn rr_address_ipv6(&mut self, ipv6_addr: &Ipv6Addr, mut prefix_length: u8) {
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

    pub(super) fn rr_address_with_prefix(&mut self, address: &Address, prefix_length: u8) {
        match address {
            Address::Ipv4(ipv4_addr) => self.rr_address_ipv4(ipv4_addr, prefix_length),
            Address::Ipv6(ipv6_addr) => self.rr_address_ipv6(ipv6_addr, prefix_length),
        }
    }
}
