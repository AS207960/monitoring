FROM rustlang/rust:nightly AS builder
RUN mkdir /new_tmp
WORKDIR /usr/src/
RUN rustup target add x86_64-unknown-linux-musl

RUN mkdir /usr/src/circuit-cards
WORKDIR /usr/src/dns-blackbox
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo install --target x86_64-unknown-linux-musl --path .

FROM scratch

COPY --from=builder --chown=0:0 /usr/local/cargo/bin/dns-blackbox /

ENTRYPOINT ["/dns-blackbox"]
