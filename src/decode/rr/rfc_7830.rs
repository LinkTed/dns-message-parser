use crate::decode::Decoder;
use crate::rr::Padding;
use crate::{DecodeError, DecodeResult};
use std::convert::TryInto;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_edns_padding(&mut self) -> DecodeResult<Padding> {
        let padding = self.vec()?;
        let padding_len = padding.len();
        match padding_len.try_into() {
            Ok(padding_len) => {
                for b in &padding {
                    if *b != 0 {
                        return Err(DecodeError::PaddingZero(*b));
                    }
                }
                Ok(Padding(padding_len))
            }
            Err(_) => Err(DecodeError::PaddingLength(padding_len)),
        }
    }
}

#[cfg(test)]
static MAX_PADDING: [u8; 65536] = [0; 65536];

#[test]
fn rr_edns_padding_length() {
    use bytes::Bytes;
    let bytes = Bytes::from_static(&MAX_PADDING[..]);
    let mut decoder = Decoder::main(bytes);
    assert_eq!(
        decoder.rr_edns_padding(),
        Err(DecodeError::PaddingLength(65536))
    );
}
