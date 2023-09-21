FROM scrolltech/cuda-go-rust-builder:cuda-11.7.1-go-1.19-rust-nightly-2022-12-10 as builder

ARG MOCK_TESTNET_FEATURE=inner-prove
ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH
WORKDIR /src
ADD . /src
RUN mkdir /.cargo && echo 'paths = ["/src/halo2-gpu/halo2_proofs"]' > /.cargo/config
RUN cargo build --features $MOCK_TESTNET_FEATURE --bin mock_testnet --release
Run cd ./target/release && find -name libzktrie.so | xargs -I {} cp {} ./
RUN apt update && apt install -y curl
RUN mkdir test_assets
RUN curl -o ./test_assets/layer1.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.1/layer1.config
RUN curl -o ./test_assets/layer2.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.1/layer2.config
RUN curl -o ./test_assets/layer3.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.1/layer3.config
RUN curl -o ./test_assets/layer4.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.1/layer4.config
RUN curl -o ./test_assets/agg_vk.vkey https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.1/agg_vk.vkey
RUN curl -o ./test_assets/chunk.protocol https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.1/chunk.protocol
RUN curl -o ./test_assets/evm_verifier.bin https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.9.1/evm_verifier.bin

FROM nvidia/cuda:11.7.1-runtime-ubuntu22.04

ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH
ENV SCROLL_PROVER_ASSETS_DIR /opt/test_assets
ENV SCROLL_PROVER_PARAMS_DIR /opt/test_params
ENV RUST_MIN_STACK 100000000
ENV RUST_BACKTRACE 1
ENV RUST_LOG trace
WORKDIR /opt
RUN mkdir -p /opt/test_assets /opt/test_logs
COPY --from=builder /src/target/release/libzktrie.so /usr/local/lib/
COPY --from=builder /src/target/release/mock_testnet /bin/
COPY --from=builder /src/test_assets/ /opt/test_assets/
COPY --from=builder /src/docker/mock-testnet/gpu/run.sh /opt/run.sh
