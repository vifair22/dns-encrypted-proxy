#!/usr/bin/env python3
import asyncio
import ssl
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived


def build_dns_response_from_query(query: bytes) -> bytes:
    if len(query) < 12:
        return b""

    response = bytearray(query)
    response[2] = (response[2] | 0x80) & 0xFF
    response[3] = response[3] & 0xF0
    response[6:12] = b"\x00\x00\x00\x00\x00\x00"
    return bytes(response)


class DoQProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stream_buf = {}

    def quic_event_received(self, event):
        if not isinstance(event, StreamDataReceived):
            return

        stream_id = event.stream_id
        buf = self._stream_buf.setdefault(stream_id, bytearray())
        if event.data:
            buf.extend(event.data)

        if len(buf) < 2:
            return

        qlen = (buf[0] << 8) | buf[1]
        if len(buf) < 2 + qlen:
            return

        query = bytes(buf[2 : 2 + qlen])
        response = build_dns_response_from_query(query)
        if not response:
            return

        framed = len(response).to_bytes(2, "big") + response
        self._quic.send_stream_data(stream_id, framed, end_stream=True)
        self.transmit()
        self._stream_buf.pop(stream_id, None)


async def main_async() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: mock_doq_server.py <port> <cert> <key>")

    port = int(sys.argv[1])
    cert = sys.argv[2]
    key = sys.argv[3]

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    configuration.verify_mode = ssl.CERT_NONE
    configuration.load_cert_chain(cert, key)

    await serve("127.0.0.1", port, configuration=configuration, create_protocol=DoQProtocol)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main_async())
