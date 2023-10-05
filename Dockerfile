FROM --platform=${TARGETPLATFORM:-linux/amd64} rust:1.72 as rust-builder

RUN apt-get update && apt-get install -y curl cmake git pkg-config libssl-dev protobuf-compiler
# Copy source files
COPY . /router
WORKDIR /router/examples/middleware

ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN rustup component add rustfmt
RUN cargo build --release

FROM --platform=${TARGETPLATFORM:-linux/amd64} gcr.io/distroless/cc-debian12

LABEL org.opencontainers.image.source=https://github.com/inigolabs/inigo-rs/router

COPY --from=rust-builder /router/examples/middleware/target/release/router /router

ENTRYPOINT ["./router"]
