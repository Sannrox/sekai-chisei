ARG BASE_IMAGE=debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

FROM ${BASE_IMAGE}

ARG VCS_REF=unknown
LABEL org.opencontainers.image.revision=$VCS_REF

# Fixed ids: deploy/kubernetes sets runAsUser and fsGroup to 999.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 999 sekai \
    && useradd --system --uid 999 --gid 999 --create-home sekai \
    && mkdir /data && chown sekai:sekai /data

COPY chisei-gateway /usr/local/bin/

VOLUME /data
EXPOSE 8788

USER sekai
CMD ["chisei-gateway"]
