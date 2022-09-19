# Build common-rs
FROM scrolltech/rust-builder:nightly-2022-08-23 as builder

RUN mkdir -p /root/src
ADD . /root/src
RUN cd /root/src && cargo build --release
