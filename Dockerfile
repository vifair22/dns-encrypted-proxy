# syntax=docker/dockerfile:1

FROM alpine:edge AS build

RUN apk add --no-cache \
    build-base \
    binutils \
    cmake \
    pkgconfig \
    curl-dev \
    openssl-dev \
    ca-certificates

WORKDIR /src

COPY CMakeLists.txt ./
COPY src ./src
COPY dns-encrypted-proxy.conf.example ./

RUN cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF \
    -DBUILD_BENCHMARKS=OFF \
    -DENABLE_UPSTREAM_DOQ=OFF \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    -DCMAKE_C_FLAGS_RELEASE="-O3 -DNDEBUG -ffunction-sections -fdata-sections" \
    -DCMAKE_EXE_LINKER_FLAGS_RELEASE="-Wl,--gc-sections" \
    && cmake --build build --target dns-encrypted-proxy -j \
    && strip /src/build/dns-encrypted-proxy

FROM alpine:edge AS runtime

RUN apk add --no-cache \
    libcurl \
    openssl \
    ca-certificates

WORKDIR /app

COPY --from=build /src/build/dns-encrypted-proxy /app/dns-encrypted-proxy
RUN mkdir -p /app/config
COPY dns-encrypted-proxy.conf.example /app/config/dns-encrypted-proxy.conf

ENV DNS_ENCRYPTED_PROXY_CONFIG=/app/config/dns-encrypted-proxy.conf

EXPOSE 53/tcp
EXPOSE 53/udp

CMD ["/app/dns-encrypted-proxy"]
