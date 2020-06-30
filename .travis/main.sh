#!/bin/bash -e


if [ "$TRAVIS_OS_NAME" = "linux" ]
then
  if [ "$TRAVIS_RUST_VERSION" = "nightly" ]
  then
    .travis/coverage.sh
  else
    # Download rustfmt
    rustup component add rustfmt
    # check fmt
    cargo fmt -- --check
    cargo test --verbose --all
  fi
else
  # rustup component add clippy
  # cargo clippy --verbose -- -D clippy::cognitive_complexity -D warnings
  # cargo clean
  cargo test --verbose --all
fi

# vim: filetype=sh ts=2 sw=2 et:
