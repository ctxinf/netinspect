#!/usr/bin/env python3
"""Small public UDP/WebSocket interactions using only the Python standard library."""
import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
import time


def udp_dns():
    query_id = os.urandom(2)
    query = query_id + bytes.fromhex('01000001000000000000076578616d706c6503636f6d0000010001')
    for host in ('1.1.1.1', '8.8.8.8'):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(4)
                client.connect((host, 53))
                client.send(query)
                response = client.recv(4096)
                if (len(response) < 12 or response[:2] != query_id
                        or not response[2] & 0x80 or response[3] & 0x0f
                        or struct.unpack('!H', response[6:8])[0] == 0):
                    raise ValueError('invalid DNS response')
                print('Validated UDP DNS response')
                return
        except (OSError, ValueError):
            continue
    raise RuntimeError('public UDP DNS resolvers did not answer successfully')


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise RuntimeError('connection closed before echo')
        result.extend(chunk)
    return bytes(result)


def send_frame(stream, opcode, payload):
    mask = os.urandom(4)
    size = len(payload)
    header = bytes([0x80 | opcode])
    if size < 126:
        header += bytes([0x80 | size])
    else:
        header += b'\xfe' + struct.pack('!H', size)
    stream.sendall(header + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))


def websocket():
    host = 'echo.websocket.org'
    payload = ('netinspect-smoke-' + os.urandom(8).hex()).encode()
    key = base64.b64encode(os.urandom(16)).decode()
    with socket.create_connection((host, 443), timeout=6) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as stream:
            stream.settimeout(6)
            stream.sendall((f'GET / HTTP/1.1\r\nHost: {host}\r\n'
                            'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                            f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
            # Read only the HTTP header, leaving any immediate welcome frame intact.
            header = bytearray()
            while not header.endswith(b'\r\n\r\n'):
                if len(header) >= 16384:
                    raise RuntimeError('oversized upgrade response')
                header.extend(read_exact(stream, 1))
            lines = header.decode('iso-8859-1').split('\r\n')
            fields = {name.lower(): value.strip() for name, value in
                      (line.split(':', 1) for line in lines[1:] if ':' in line)}
            accept = base64.b64encode(hashlib.sha1(
                (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            if (lines[0].split()[1] != '101'
                    or fields.get('sec-websocket-accept', '').strip() != accept
                    or fields.get('upgrade', '').lower() != 'websocket'
                    or 'upgrade' not in fields.get('connection', '').lower()):
                raise RuntimeError('WebSocket upgrade rejected')
            send_frame(stream, 1, payload)
            message = bytearray()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                stream.settimeout(max(.1, min(4, deadline - time.monotonic())))
                a, b = read_exact(stream, 2)
                opcode, size = a & 0x0f, b & 0x7f
                if b & 0x80:
                    raise RuntimeError('server sent a masked frame')
                if size == 126:
                    size = struct.unpack('!H', read_exact(stream, 2))[0]
                elif size == 127:
                    size = struct.unpack('!Q', read_exact(stream, 8))[0]
                if size > 65536 or len(message) + size > 65536:
                    raise RuntimeError('oversized echo frame')
                body = read_exact(stream, size)
                if opcode == 8:
                    raise RuntimeError('server closed before echo')
                if opcode == 9:
                    send_frame(stream, 10, body)
                elif opcode in (0, 1, 2):
                    if opcode != 0:
                        message.clear()
                    message.extend(body)
                    if a & 0x80:
                        if message == payload:
                            send_frame(stream, 8, struct.pack('!H', 1000))
                            print('Validated TLS upgrade and WebSocket message echo')
                            return
                        message.clear()  # The public service can send a welcome message.
            raise RuntimeError('WebSocket echo not received')


if __name__ == '__main__':
    {'udp': udp_dns, 'ws': websocket}[sys.argv[1]]()
