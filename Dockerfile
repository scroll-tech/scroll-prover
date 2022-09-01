# Build common-rs
FROM scrolltech/rust-builder as builder

RUN mkdir -p /root/src
ADD . /root/src
RUN cd /root/src && cargo build --release
