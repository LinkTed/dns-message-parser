#[macro_use]
extern crate afl;
use bytes::Bytes;
use dns_message_parser::Dns;

fn main() {
    fuzz!(|data: &[u8]| {
        let bytes = Bytes::copy_from_slice(data);
        if let Ok(dns_1) = Dns::decode(bytes) {
            match dns_1.encode() {
                Ok(bytes) => match Dns::decode(bytes.freeze()) {
                    Ok(dns_2) => {
                        if dns_1 != dns_2 {
                            panic!(
                                "Packet is not equal: {:?} != {:?}: {:?}",
                                dns_1, dns_2, data
                            );
                        }
                    }
                    Err(e) => {
                        panic!(
                            "Could not decode DNS packet: {:?}: {:?}: {:?}",
                            e, data, dns_1
                        );
                    }
                },
                Err(e) => {
                    panic!(
                        "Could not encode DNS packet: {:?}: {:?}: {:?}",
                        e, data, dns_1
                    );
                }
            }
        }
    });
}
