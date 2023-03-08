FROM --platform=$BUILDPLATFORM rust:1.67-slim as rust-builder

RUN apt-get update && apt-get install -y curl git pkg-config libssl-dev protobuf-compiler
# Copy source files
COPY . /router
WORKDIR /router/examples/middleware

ARG TARGETPLATFORM
RUN case "$TARGETPLATFORM" in \
  "linux/arm64") echo aarch64-unknown-linux-gnu > /target.txt ;; \
  "linux/amd64") echo x86_64-unknown-linux-gnu > /target.txt ;; \
  *) exit 1 ;; \
esac

ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN rustup component add rustfmt
RUN cargo build --release --target $(cat /target.txt)

FROM gcr.io/distroless/cc-debian11

LABEL org.opencontainers.image.source=https://github.com/inigolabs/inigo-rs/router

COPY --from=rust-builder /router/examples/middleware/target/release/router /router

ENTRYPOINT ["./router"]