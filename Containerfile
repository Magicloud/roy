FROM ghcr.io/magicloud/rust-stable:latest AS builder

RUN cargo install bpf-linker && rustup toolchain install nightly --component rust-src

WORKDIR /usr/src/myapp
COPY . .

RUN cargo install --path roy


FROM debian:trixie

# EXPOSE 443/TCP

COPY --from=builder /usr/local/cargo/bin/roy /usr/local/bin/roy

ENTRYPOINT ["roy"]
