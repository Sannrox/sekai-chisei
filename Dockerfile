# syntax=docker/dockerfile:1
#
# Checkout-build recovery path for `docker compose up --build` and GHCR.
# Canonical local wrap of prebuilt linux binaries: `make release-images`.

FROM rust:1.98.1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS builder

WORKDIR /app
COPY . .
ARG VCS_REF=unknown
ARG GIT_VERSION=
ENV SEKAI_GIT_COMMIT=$VCS_REF
ENV SEKAI_GIT_VERSION=$GIT_VERSION
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --workspace --bins && \
    mkdir -p /out && \
    cp target/release/sekai-chisei \
       target/release/chisei-gateway \
       target/release/sekaictl /out/

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ARG VCS_REF=unknown
LABEL org.opencontainers.image.revision=$VCS_REF

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home sekai \
    && mkdir /data && chown sekai:sekai /data

COPY --from=builder /out/ /usr/local/bin/

ENV DB_PATH=/data/sekai.db \
    SEKAI_SOCKET=/data/sekai.sock

VOLUME /data
EXPOSE 50051

USER sekai
CMD ["sekai-chisei"]
