macro_rules! impl_decode_rr_domain_name {
    ($i:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(
            &mut self,
            header: super::enums::Header,
        ) -> crate::DecodeResult<crate::rr::$i> {
            let class = header.get_class()?;
            let $n = self.domain_name()?;
            let v = crate::rr::$i {
                domain_name: header.domain_name,
                ttl: header.ttl,
                class,
                $n,
            };
            Ok(v)
        }
    };
}

macro_rules! impl_decode_rr_u16_domain_name {
    ($i:ident, $p:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(
            &mut self,
            header: super::enums::Header,
        ) -> crate::DecodeResult<crate::rr::$i> {
            let class = header.get_class()?;
            let $p = self.u16()?;
            let $n = self.domain_name()?;
            let v = crate::rr::$i {
                domain_name: header.domain_name,
                ttl: header.ttl,
                class,
                $p,
                $n,
            };
            Ok(v)
        }
    };
}

macro_rules! impl_decode_rr_u16_u64 {
    ($i:ident, $p:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(
            &mut self,
            header: super::enums::Header,
        ) -> crate::DecodeResult<crate::rr::$i> {
            let class = header.get_class()?;
            let $p = self.u16()?;
            let $n = self.u64()?;
            let v = crate::rr::$i {
                domain_name: header.domain_name,
                ttl: header.ttl,
                class,
                $p,
                $n,
            };
            Ok(v)
        }
    };
}

macro_rules! impl_decode_rr_domain_name_domain_name {
    ($i:ident, $p:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(
            &mut self,
            header: super::enums::Header,
        ) -> crate::DecodeResult<crate::rr::$i> {
            let class = header.get_class()?;
            let $p = self.domain_name()?;
            let $n = self.domain_name()?;
            let v = crate::rr::$i {
                domain_name: header.domain_name,
                ttl: header.ttl,
                class,
                $p,
                $n,
            };
            Ok(v)
        }
    };
}

macro_rules! impl_decode_rr_vec {
    ($i:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(
            &mut self,
            header: super::enums::Header,
        ) -> crate::DecodeResult<crate::rr::$i> {
            let class = header.get_class()?;
            let $n = self.vec()?;
            let v = crate::rr::$i {
                domain_name: header.domain_name,
                ttl: header.ttl,
                class,
                $n,
            };
            Ok(v)
        }
    };
}

macro_rules! impl_decode_rr_string {
    ($i:ident, $n:ident, $m:ident) => {
        pub(super) fn $m(
            &mut self,
            header: super::enums::Header,
        ) -> crate::DecodeResult<crate::rr::$i> {
            let class = header.get_class()?;
            let $n = self.string()?;
            let v = crate::rr::$i {
                domain_name: header.domain_name,
                ttl: header.ttl,
                class,
                $n,
            };
            Ok(v)
        }
    };
}
