FROM --platform=linux/amd64 rust:1.65-slim as rust-builder

RUN apt-get update && apt-get install -y curl pkg-config libssl-dev protobuf-compiler
# Copy source files
COPY . /router
WORKDIR /router/examples/middleware

RUN rustup component add rustfmt
RUN cargo build --release

FROM --platform=linux/amd64 gcr.io/distroless/cc-debian11

LABEL org.opencontainers.image.source=https://github.com/inigolabs/inigo-rs/router

COPY --from=rust-builder /router/examples/middleware/target/release/router /router

ENTRYPOINT ["./router"]