macro_rules! try_from_enum_to_integer {
    (
        #[repr($integer:ident)]
        $(#[$meta:meta])*
        $visibility:vis enum $enum:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:expr
            ),*
            $( , )?
        }
    ) => {
        $(#[$meta])*
        #[repr($integer)]
        $visibility enum $enum {
            $(
                $(#[$variant_meta])*
                $variant = $value
            ),*
        }

        impl std::convert::TryFrom<$integer> for $enum {
            type Error = $integer;

            fn try_from(value: $integer) -> Result<$enum, $integer> {
                match value {
                    $(
                        $value => Ok($enum::$variant),
                    )*
                    value => Err(value)
                }
            }
        }

        impl std::fmt::Display for $enum {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        $enum::$variant => write!(f, stringify!($variant)),
                    )*
                }
            }
        }
    }
}

macro_rules! try_from_enum_to_integer_without_display {
    (
        #[repr($integer:ident)]
        $(#[$meta:meta])*
        $visibility:vis enum $enum:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:expr
            ),*
            $( , )?
        }
    ) => {
        $(#[$meta])*
        #[repr($integer)]
        $visibility enum $enum {
            $(
                $(#[$variant_meta])*
                $variant = $value
            ),*
        }

        impl std::convert::TryFrom<$integer> for $enum {
            type Error = $integer;

            fn try_from(value: $integer) -> Result<$enum, $integer> {
                match value {
                    $(
                        $value => Ok($enum::$variant),
                    )*
                    value => Err(value)
                }
            }
        }
    }
}
