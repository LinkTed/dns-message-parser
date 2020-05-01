#!/bin/bash -e

if [ "$TRAVIS_RUST_VERSION" = "nightly" ]
then
  if [ "$TRAVIS_OS_NAME" = "linux" ]
  then
    # Download and unpack grcov
    curl -L https://github.com/mozilla/grcov/releases/latest/download/grcov-linux-x86_64.tar.bz2 | tar jxf -
    # Set environment variables
    export CARGO_INCREMENTAL=0
    export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 \
    -Clink-dead-code -Coverflow-checks=off"
    # Create code coverage (gcno and gcda files)
    cargo test --verbose --all
    # Pack the gcno and gcda files into a zip file
    zip -0 ccov.zip `find . \( -name "dns_message_parser*.gc*" \) -print`
    # Convert gcno and gcda files into lcov
    ./grcov ccov.zip -s . -t lcov --llvm --branch \
    --ignore-not-existing --ignore "/*" -o lcov.info
    # Upload code coverage
    bash <(curl -s https://codecov.io/bash) -f lcov.info
  else
    cargo test --verbose --all
  fi
else
  # rustup component add clippy
  # cargo clippy --verbose -- -D clippy::cognitive_complexity -D warnings
  # cargo clean
  cargo test --verbose --all
fi

# vim: filetype=sh ts=2 sw=2 et:
