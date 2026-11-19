# syntax=docker/dockerfile:1

FROM alpine:edge AS build

RUN apk add --no-cache \
    build-base \
    binutils \
    git \
    pkgconfig \
    curl-dev \
    openssl-dev \
    ca-certificates

WORKDIR /src

COPY Makefile ./
COPY release_version ./
COPY src ./src
COPY dns-encrypted-proxy.conf.example ./

ARG C_LOG_CACHE_BUST=1
RUN rm -rf /opt/c-log && echo "$C_LOG_CACHE_BUST" >/tmp/c_log_cache_bust && git clone --depth 1 https://git.airies.net/vifair22/c-log /opt/c-log

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
