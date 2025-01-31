ARG TARGETARCH

FROM ubuntu:latest AS base
LABEL org.opencontainers.image.source="https://github.com/inigolabs/inigo-rs/router"

FROM base AS build_arm64
COPY examples/router/target/aarch64-unknown-linux-gnu/release/router /router

FROM base AS build_amd64
COPY examples/router/target/x86_64-unknown-linux-gnu/release/router /router

FROM build_${TARGETARCH}
ENTRYPOINT ["/router"]