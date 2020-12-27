macro_rules! impl_to_type {
    ($i:ident) => {
        impl crate::rr::ToType for $i {
            fn to_type(&self) -> crate::rr::Type {
                crate::rr::Type::$i
            }
        }
    };
}

macro_rules! struct_domain_name {
    ($(#[$doc_comment:meta])* $i:ident, $n:ident) => {
        $(#[$doc_comment])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $i {
            pub domain_name: crate::DomainName,
            pub ttl: u32,
            pub class: super::Class,
            pub $n: crate::DomainName,
        }

        impl_to_type!($i);

        impl std::fmt::Display for $i {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{} {} {} {} {}",
                    self.domain_name,
                    self.ttl,
                    self.class,
                    stringify!($i),
                    self.$n
                )
            }
        }
    };
}

macro_rules! struct_vec {
    ($(#[$doc_comment:meta])* $i:ident, $n:ident) => {
        $(#[$doc_comment])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $i {
            pub domain_name: crate::DomainName,
            pub ttl: u32,
            pub class: super::Class,
            pub $n: Vec<u8>,
        }

        impl_to_type!($i);

        impl std::fmt::Display for $i {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{} {} {} {} {}",
                    self.domain_name,
                    self.ttl,
                    self.class,
                    stringify!($i),
                    hex::encode(&self.$n),
                )
            }
        }
    };
}

macro_rules! struct_domain_name_domain_name {
    ($(#[$doc_comment:meta])* $i:ident, $n:ident, $m:ident) => {
        $(#[$doc_comment])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $i {
            pub domain_name: crate::DomainName,
            pub ttl: u32,
            pub class: super::Class,
            pub $n: crate::DomainName,
            pub $m: crate::DomainName,
        }

        impl_to_type!($i);

        impl std::fmt::Display for $i {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{} {} {} {} {} {}",
                    self.domain_name,
                    self.ttl,
                    self.class,
                    stringify!($i),
                    self.$n,
                    self.$m
                )
            }
        }
    };
}

macro_rules! struct_u16_domain_name {
    ($(#[$doc_comment:meta])* $i:ident, $n:ident, $m:ident) => {
        $(#[$doc_comment])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $i {
            pub domain_name: crate::DomainName,
            pub ttl: u32,
            pub class: super::Class,
            pub $n: u16,
            pub $m: crate::DomainName,
        }

        impl_to_type!($i);

        impl std::fmt::Display for $i {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{} {} {} {} {} {}",
                    self.domain_name,
                    self.ttl,
                    self.class,
                    stringify!($i),
                    self.$n,
                    self.$m
                )
            }
        }
    };
}

macro_rules! struct_string {
    ($(#[$doc_comment:meta])* $i:ident, $n:ident) => {
        $(#[$doc_comment])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $i {
            pub domain_name: crate::DomainName,
            pub ttl: u32,
            pub class: super::Class,
            pub $n: String,
        }

        impl_to_type!($i);

        impl std::fmt::Display for $i {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{} {} {} {} {}",
                    self.domain_name,
                    self.ttl,
                    self.class,
                    stringify!($i),
                    self.$n
                )
            }
        }
    };
}

macro_rules! struct_u16_u64 {
    ($(#[$doc_comment:meta])* $i:ident, $n:ident, $m:ident) => {
        $(#[$doc_comment])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $i {
            pub domain_name: crate::DomainName,
            pub ttl: u32,
            pub class: super::Class,
            pub $n: u16,
            pub $m: u64,
        }

        impl_to_type!($i);

        impl std::fmt::Display for $i {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let bytes = self.$m.to_be_bytes();
                write!(
                    f,
                    "{} {} {} {} {} {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    self.domain_name,
                    self.ttl,
                    self.class,
                    stringify!($i),
                    self.$n,
                    bytes[0],
                    bytes[1],
                    bytes[2],
                    bytes[3],
                    bytes[4],
                    bytes[5],
                    bytes[6],
                    bytes[7],
                )
            }
        }
    };
}
