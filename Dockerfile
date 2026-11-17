# syntax=docker/dockerfile:1

FROM alpine:edge AS build

RUN apk add --no-cache \
    build-base \
    bash \
    binutils \
    git \
    pkgconfig \
    curl-dev \
    openssl-dev \
    ca-certificates

WORKDIR /src

# Copied ahead of src so a c-log pin change, and only that, refetches it.
COPY tools/fetch_c_log.sh tools/c-log.ref ./tools/
RUN tools/fetch_c_log.sh /opt/c-log

COPY Makefile ./
COPY release_version ./
COPY src ./src
COPY dns-encrypted-proxy.conf.example ./

RUN make -j"$(nproc)" proxy BUILD=release DOQ=0 C_LOG_PATH=/opt/c-log \
    && strip /src/build/bin/dns-encrypted-proxy

FROM alpine:edge AS runtime

RUN apk add --no-cache \
    libcurl \
    openssl \
    ca-certificates

WORKDIR /app

COPY --from=build /src/build/bin/dns-encrypted-proxy /app/dns-encrypted-proxy
RUN mkdir -p /app/config
COPY dns-encrypted-proxy.conf.example /app/config/dns-encrypted-proxy.conf

ENV DNS_ENCRYPTED_PROXY_CONFIG=/app/config/dns-encrypted-proxy.conf

EXPOSE 53/tcp
EXPOSE 53/udp

CMD ["/app/dns-encrypted-proxy"]
