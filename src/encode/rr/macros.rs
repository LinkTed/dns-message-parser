macro_rules! impl_encode_rr_domain_name {
    ($i:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(&mut self, i: &crate::rr::$i) -> crate::EncodeResult<()> {
            self.domain_name(&i.domain_name)?;
            self.rr_type(&crate::rr::Type::$i);
            self.rr_class(&i.class);
            self.u32(i.ttl);
            let length_index = self.create_length_index();
            self.domain_name(&i.$n)?;
            self.set_length_index(length_index)
        }
    };
}

macro_rules! impl_encode_rr_domain_name_domain_name {
    ($i:ident, $p:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(&mut self, i: &crate::rr::$i) -> crate::EncodeResult<()> {
            self.domain_name(&i.domain_name)?;
            self.rr_type(&crate::rr::Type::$i);
            self.rr_class(&i.class);
            self.u32(i.ttl);
            let length_index = self.create_length_index();
            self.domain_name(&i.$p)?;
            self.domain_name(&i.$n)?;
            self.set_length_index(length_index)
        }
    };
}

macro_rules! impl_encode_rr_u16_domain_name {
    ($i:ident, $p:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(&mut self, i: &crate::rr::$i) -> crate::EncodeResult<()> {
            self.domain_name(&i.domain_name)?;
            self.rr_type(&crate::rr::Type::$i);
            self.rr_class(&i.class);
            self.u32(i.ttl);
            let length_index = self.create_length_index();
            self.u16(i.$p);
            self.domain_name(&i.$n)?;
            self.set_length_index(length_index)
        }
    };
}

macro_rules! impl_encode_rr_u16_u64 {
    ($i:ident, $p:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(&mut self, i: &crate::rr::$i) -> crate::EncodeResult<()> {
            self.domain_name(&i.domain_name)?;
            self.rr_type(&crate::rr::Type::$i);
            self.rr_class(&i.class);
            self.u32(i.ttl);
            let length_index = self.create_length_index();
            self.u16(i.$p);
            self.u64(i.$n);
            self.set_length_index(length_index)
        }
    };
}

macro_rules! impl_encode_rr_vec {
    ($i:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(&mut self, i: &crate::rr::$i) -> crate::EncodeResult<()> {
            self.domain_name(&i.domain_name)?;
            self.rr_type(&crate::rr::Type::$i);
            self.rr_class(&i.class);
            self.u32(i.ttl);
            let length_index = self.create_length_index();
            self.bytes.extend_from_slice(&i.$n);
            self.set_length_index(length_index)
        }
    };
}

macro_rules! impl_encode_rr {
    ($i:ident, $m:ident) => {
        impl_encode!(crate::rr::$i, $m);
    };
}
