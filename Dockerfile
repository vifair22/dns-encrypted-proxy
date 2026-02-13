# syntax=docker/dockerfile:1

FROM alpine:3.19 AS build

RUN apk add --no-cache \
    build-base \
    cmake \
    pkgconfig \
    curl-dev \
    ca-certificates

WORKDIR /src

COPY CMakeLists.txt ./
COPY src ./src
COPY doh-proxy.conf.example ./

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j

FROM alpine:3.19 AS runtime

RUN apk add --no-cache \
    libcurl \
    ca-certificates

WORKDIR /app

COPY --from=build /src/build/DOH-Proxy /app/DOH-Proxy
COPY doh-proxy.conf.example /app/doh-proxy.conf.example

EXPOSE 53/tcp
EXPOSE 53/udp

CMD ["/app/DOH-Proxy"]
