FROM scrolltech/cuda-go-rust-builder:cuda-11.7.1-go-1.19-rust-nightly-2022-12-10 as builder

WORKDIR /
COPY halo2-gpu /halo2-gpu
RUN echo 'paths = ["/halo2-gpu/halo2_proofs"]' > /root/.cargo/config
ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH

COPY scroll-prover /scroll-prover
RUN <<EOF bash
pushd /scroll-prover
cargo build --release --bin zkevm_prove
pushd ./target/release
find -name libzktrie.so | xargs -I {} cp {} ./
popd
popd
EOF

FROM nvidia/cuda:11.7.1-runtime-ubuntu22.04

RUN apt update && apt install -y curl

ENV LD_LIBRARY_PATH usr/local/cuda/lib64:$LD_LIBRARY_PATH
ENV CHAIN_ID 534351
ENV RUST_BACKTRACE full
ENV RUST_LOG trace
ENV RUST_MIN_STACK 100000000

WORKDIR /
COPY --from=builder /scroll-prover/target/release/zkevm_prove /bin/
COPY --from=builder /scroll-prover/target/release/libzktrie.so /usr/lib

RUN mkdir -p /integration/configs /integration/test_params /integration/test_traces
RUN curl -o /integration/configs/layer1.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.4/layer1.config
RUN curl -o /integration/configs/layer2.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.4/layer2.config
RUN curl -o /integration/test_params/params20 https://circuit-release.s3.us-west-2.amazonaws.com/setup/params20
RUN curl -o /integration/test_params/params24 https://circuit-release.s3.us-west-2.amazonaws.com/setup/params24
COPY --from=builder /scroll-prover/integration/tests/extra_traces/new.json /integration/test_traces

RUN mkdir -p /integration/test_assets
RUN curl -o /integration/test_assets/chunk_vk.vkey https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.4/chunk_vk.vkey
