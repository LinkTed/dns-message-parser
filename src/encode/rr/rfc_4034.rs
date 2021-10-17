use crate::encode::Encoder;
use crate::rr::{AlgorithmType, DigestType, Type, DNSKEY, DS};
use crate::EncodeResult;

impl Encoder {
    fn rr_algorithm_type(&mut self, algorithm_type: AlgorithmType) {
        self.u8(algorithm_type as u8);
    }

    fn rr_digest_type(&mut self, digest_type: DigestType) {
        self.u8(digest_type as u8);
    }

    pub(super) fn rr_dnskey(&mut self, dnskey: &DNSKEY) -> EncodeResult<()> {
        self.domain_name(&dnskey.domain_name)?;
        self.rr_type(&Type::DNSKEY);
        self.rr_class(&dnskey.class);
        self.u32(dnskey.ttl);
        let length_index = self.create_length_index();
        self.u16(dnskey.get_flags());
        self.u8(3);
        self.rr_algorithm_type(dnskey.algorithm_type);
        self.vec(&dnskey.public_key);
        self.set_length_index(length_index)
    }

    pub(super) fn rr_ds(&mut self, ds: &DS) -> EncodeResult<()> {
        self.domain_name(&ds.domain_name)?;
        self.rr_type(&Type::DS);
        self.rr_class(&ds.class);
        self.u32(ds.ttl);
        let length_index = self.create_length_index();
        self.u16(ds.key_tag);
        self.rr_algorithm_type(ds.algorithm_type);
        self.rr_digest_type(ds.digest_type);
        self.vec(&ds.digest);
        self.set_length_index(length_index)
    }
}
