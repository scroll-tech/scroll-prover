FROM scrolltech/cuda-go-rust-builder:cuda-11.7.1-go-1.21-rust-nightly-2023-12-03 as builder

ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH
WORKDIR /src
ADD . /src
RUN mkdir /.cargo && echo 'paths = ["/src/halo2-gpu/halo2_proofs"]' > /.cargo/config
RUN cargo build --bin trace_prover --release
RUN apt update && apt install -y curl
RUN mkdir test_assets
RUN curl -o ./test_assets/layer1.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.11.0rc8/layer1.config
RUN curl -o ./test_assets/layer2.config https://circuit-release.s3.us-west-2.amazonaws.com/release-v0.11.0rc8/layer2.config

FROM nvidia/cuda:11.7.1-runtime-ubuntu22.04

ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH
ENV SCROLL_PROVER_ASSETS_DIR /opt/test_assets
ENV SCROLL_PROVER_PARAMS_DIR /opt/test_params
ENV RUST_MIN_STACK 100000000
ENV RUST_BACKTRACE 1
ENV RUST_LOG debug
WORKDIR /opt
RUN mkdir -p /opt/test_assets
COPY --from=builder /src/target/release/trace_prover /bin/
COPY --from=builder /src/test_assets/ /opt/test_assets/
