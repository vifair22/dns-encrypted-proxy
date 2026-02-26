#!/usr/bin/env python3
import argparse
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def build_dns_response(query: bytes, answer_count: int) -> bytes:
    if len(query) < 12:
        return b""

    qdcount = query[4:6]
    question = query[12:]

    header = bytearray(12)
    header[0:2] = query[0:2]
    header[2] = 0x81
    header[3] = 0x80
    header[4:6] = qdcount
    if answer_count < 1:
        answer_count = 1
    header[6:8] = bytes([(answer_count >> 8) & 0xFF, answer_count & 0xFF])
    header[8:10] = b"\x00\x00"
    header[10:12] = b"\x00\x00"

    parts = [bytes(header), question]
    for i in range(answer_count):
        octet = 1 + (i % 250)
        answer = b"\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x01\x01\x01" + bytes([octet])
        parts.append(answer)
    return b"".join(parts)


class DnsHandler(BaseHTTPRequestHandler):
    delay_us = 0
    answer_count = 1

    def do_POST(self):
        if self.path != "/dns-query":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        if DnsHandler.delay_us > 0:
            time.sleep(DnsHandler.delay_us / 1_000_000.0)

        resp = build_dns_response(body, DnsHandler.answer_count)
        if not resp:
            self.send_error(400)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format, *args):
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Mock DoH server for proxy e2e benchmarking")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--delay-us", type=int, default=0)
    parser.add_argument("--answer-count", type=int, default=1)
    args = parser.parse_args()

    DnsHandler.delay_us = max(0, args.delay_us)
    DnsHandler.answer_count = max(1, args.answer_count)

    server = ThreadingHTTPServer((args.host, args.port), DnsHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
