use super::Header;
use crate::decode::Decoder;
use crate::rr::{SSHFPAlgorithm, SSHFPType, SSHFP};
use crate::{DecodeError, DecodeResult};
use num_traits::FromPrimitive;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn rr_sshfp_algorithm(&mut self) -> DecodeResult<SSHFPAlgorithm> {
        let buffer = self.u8()?;
        if let Some(algorithm) = SSHFPAlgorithm::from_u8(buffer) {
            Ok(algorithm)
        } else {
            Err(DecodeError::SSHFPAlgorithm(buffer))
        }
    }

    fn rr_sshfp_type(&mut self) -> DecodeResult<SSHFPType> {
        let buffer = self.u8()?;
        if let Some(algorithm) = SSHFPType::from_u8(buffer) {
            Ok(algorithm)
        } else {
            Err(DecodeError::SSHFPType(buffer))
        }
    }

    pub(super) fn rr_sshfp(&mut self, header: Header) -> DecodeResult<SSHFP> {
        let class = header.get_class()?;
        let algorithm = self.rr_sshfp_algorithm()?;
        let type_ = self.rr_sshfp_type()?;
        let fp = self.vec()?;
        let ssh_fp = SSHFP {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            algorithm,
            type_,
            fp,
        };
        Ok(ssh_fp)
    }
}
