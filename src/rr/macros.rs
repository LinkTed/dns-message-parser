macro_rules! impl_to_type {
    ($i:ident) => {
        impl super::ToType for $i {
            fn to_type(&self) -> super::Type {
                super::Type::$i
            }
        }
    };
}

macro_rules! struct_domain_name {
    ($i:ident, $n:ident) => {
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
    ($i:ident, $n:ident) => {
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
    ($i:ident, $n:ident, $m:ident) => {
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
    ($i:ident, $n:ident, $m:ident) => {
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
    ($i:ident, $n:ident) => {
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
