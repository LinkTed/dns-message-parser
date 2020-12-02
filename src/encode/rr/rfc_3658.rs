use crate::encode::Encoder;
use crate::rr::{SSHFPAlgorithm, SSHFPType, Type, SSHFP};
use crate::{EncodeError, EncodeResult};
use num_traits::ToPrimitive;

impl Encoder {
    fn rr_sshfp_algorithm(&mut self, algorihtm: &SSHFPAlgorithm) -> EncodeResult<()> {
        if let Some(buffer) = algorihtm.to_u8() {
            self.u8(buffer);
            Ok(())
        } else {
            Err(EncodeError::SSHFPAlgorithmError(algorihtm.clone()))
        }
    }

    fn rr_sshfp_type(&mut self, type_: &SSHFPType) -> EncodeResult<()> {
        if let Some(buffer) = type_.to_u8() {
            self.u8(buffer);
            Ok(())
        } else {
            Err(EncodeError::SSHFPTypeError(type_.clone()))
        }
    }

    pub(super) fn rr_sshfp(&mut self, ssh_fp: &SSHFP) -> EncodeResult<()> {
        self.domain_name(&ssh_fp.domain_name)?;
        self.rr_type(&Type::SSHFP)?;
        self.rr_class(&ssh_fp.class)?;
        self.u32(ssh_fp.ttl);
        let length_index = self.create_length_index();
        self.rr_sshfp_algorithm(&ssh_fp.algorithm)?;
        self.rr_sshfp_type(&ssh_fp.type_)?;
        self.vec(&ssh_fp.fp);
        self.set_length_index(length_index)
    }
}

impl_encode_rr!(SSHFP, rr_sshfp);
