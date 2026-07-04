# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --bins && \
    mkdir -p /out && \
    cp target/release/sekai-chisei \
       target/release/chisei-gateway \
       target/release/sekaictl /out/

FROM debian:bookworm-slim

RUN useradd --system --create-home sekai && \
    mkdir /data && chown sekai:sekai /data

COPY --from=builder /out/ /usr/local/bin/

ENV DB_PATH=/data/sekai.db \
    SEKAI_SOCKET=/data/sekai.sock

VOLUME /data
EXPOSE 50051

USER sekai
CMD ["sekai-chisei"]
