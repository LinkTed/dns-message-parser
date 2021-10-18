use crate::encode::Encoder;
use crate::rr::{SSHFPAlgorithm, SSHFPType, Type, SSHFP};
use crate::EncodeResult;

impl Encoder {
    #[inline]
    fn rr_sshfp_algorithm(&mut self, algorihtm: &SSHFPAlgorithm) {
        self.u8(*algorihtm as u8);
    }

    #[inline]
    fn rr_sshfp_type(&mut self, type_: &SSHFPType) {
        self.u8(*type_ as u8);
    }

    pub(super) fn rr_sshfp(&mut self, ssh_fp: &SSHFP) -> EncodeResult<()> {
        self.domain_name(&ssh_fp.domain_name)?;
        self.rr_type(&Type::SSHFP);
        self.rr_class(&ssh_fp.class);
        self.u32(ssh_fp.ttl);
        let length_index = self.create_length_index();
        self.rr_sshfp_algorithm(&ssh_fp.algorithm);
        self.rr_sshfp_type(&ssh_fp.type_);
        self.vec(&ssh_fp.fp);
        self.set_length_index(length_index)
    }
}

impl_encode_rr!(SSHFP, rr_sshfp);
