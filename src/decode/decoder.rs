use crate::{DecodeError, DecodeResult};
use bytes::Bytes;
use std::cmp::Ordering;

pub(crate) struct Decoder<'a, 'b: 'a> {
    pub parent: Option<&'a Decoder<'b, 'b>>,
    pub(super) bytes: Bytes,
    pub(super) offset: usize,
}

impl<'a, 'b: 'a> Decoder<'b, 'b> {
    pub(super) fn sub(&'a mut self, sub_length: u16) -> DecodeResult<Decoder<'a, 'b>> {
        let bytes = self.read(sub_length as usize)?;
        let decoder = Decoder::<'a, 'b> {
            parent: Some(self),
            bytes,
            offset: 0,
        };
        Ok(decoder)
    }
}

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(crate) fn main(bytes: Bytes) -> Decoder<'static, 'static> {
        Decoder {
            parent: None,
            bytes,
            offset: 0,
        }
    }

    pub(super) fn new_main_offset(&self, offset: usize) -> Decoder<'static, 'static> {
        let main = self.get_main();
        Decoder {
            parent: None,
            bytes: main.bytes.clone(),
            offset,
        }
    }

    pub(super) fn get_main(&'a self) -> &Decoder<'a, 'b> {
        let mut root = self;
        loop {
            match root.parent {
                Some(parent) => root = parent,
                None => return root,
            }
        }
    }

    pub(super) fn is_finished(&self) -> DecodeResult<bool> {
        let bytes_len = self.bytes.len();
        match self.offset.cmp(&bytes_len) {
            Ordering::Less => Ok(false),
            Ordering::Equal => Ok(true),
            Ordering::Greater => Err(DecodeError::NotEnoughBytes(bytes_len, self.offset)),
        }
    }

    pub(super) fn finished(self) -> DecodeResult<()> {
        match self.is_finished()? {
            true => Ok(()),
            false => Err(DecodeError::TooManyBytes(self.bytes.len(), self.offset)),
        }
    }

    pub(super) fn read(&mut self, length: usize) -> DecodeResult<Bytes> {
        let start = self.offset;
        self.offset += length;
        if self.offset <= self.bytes.len() {
            Ok(self.bytes.slice(start..self.offset))
        } else {
            Err(DecodeError::NotEnoughBytes(self.bytes.len(), self.offset))
        }
    }
}

macro_rules! impl_decode {
    ($i:path, $m:ident) => {
        impl $i {
            pub fn decode(bytes: bytes::Bytes) -> crate::DecodeResult<$i> {
                let mut decoder = crate::decode::Decoder::main(bytes);
                decoder.$m()
            }
        }
    };
}
