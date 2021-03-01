use crate::rr::Class;
use crate::DomainName;
use hex::encode;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// The bit at offset 7 of the DNSKEY flags field is the [Zone Key flag].
///
/// [Zone Key flag]: https://tools.ietf.org/html/rfc4034#section-2.1.1
pub const ZONE_KEY_FLAG: u16 = 0b0000_0001_0000_0000;
/// The  bit at offset 15 of the DNSKEY flags field is the [Secure Entry Point flag].
///
/// [Secure Entry Point flag]: https://tools.ietf.org/html/rfc4034#section-2.1.1
pub const SECURE_ENTRY_POINT_FLAG: u16 = 0b0000_0000_0000_0001;
pub const DNSKEY_ZERO_MASK: u16 = 0b1111_1110_1111_1110;

try_from_enum_to_integer! {
    #[repr(u8)]
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    /// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    pub enum AlgorithmType {
        Reserved = 0x00,
        RsaMd5 = 0x01,
        DiffiHellman = 0x02,
        DsaSha1 = 0x03,
        EllipticCurve = 0x04,
        RsaSha1 = 0x05,
        DsaNsec3 = 0x06,
        RsaSha1Nsec3Sha1 = 0x07,
        RsaSha256 = 0x08,
        GostR = 0x0c,
        EcDsaP256 = 0x0d,
        EcDsaP386 = 0x0e,
        Ed25519 = 0x0f,
        Ed448 = 0x10,
        Indirect = 0xfc,
        PrivateDns = 0xfd,
        PrivateOid = 0xfe,
    }
}

try_from_enum_to_integer! {
    #[repr(u8)]
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    /// https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1
    pub enum DigestType {
        Reserved = 0x00,
        Sha1 = 0x01,
        Sha256 = 0x02,
        GostR = 0x03,
        Sha384 = 0x04,
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct DNSKEY {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub zone_key_flag: bool,
    pub secure_entry_point_flag: bool,
    pub algorithm_type: AlgorithmType,
    pub public_key: Vec<u8>,
}

impl DNSKEY {
    pub fn get_flags(&self) -> u16 {
        let mut flags: u16 = 0;
        if self.zone_key_flag {
            flags |= ZONE_KEY_FLAG;
        }
        if self.secure_entry_point_flag {
            flags |= SECURE_ENTRY_POINT_FLAG;
        }
        flags
    }
}

impl Display for DNSKEY {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} DNSKEY {} 3 {} {}",
            self.domain_name,
            self.ttl,
            self.class,
            self.get_flags(),
            self.algorithm_type.clone() as u8,
            encode(&self.public_key),
        )
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct DS {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub key_tag: u16,
    pub algorithm_type: AlgorithmType,
    pub digest_type: DigestType,
    pub digest: Vec<u8>,
}

impl Display for DS {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} DS {} {} {} {}",
            self.domain_name,
            self.ttl,
            self.class,
            self.key_tag,
            self.algorithm_type.clone() as u8,
            self.digest_type.clone() as u8,
            encode(&self.digest),
        )
    }
}
