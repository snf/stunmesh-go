#!/usr/bin/env python3
"""Initialize only the disposable network created by sandbox.py --net-admin."""
import fcntl
import os
import socket
import struct
import sys

if os.environ.get('STUNMESH_ISOLATED_TEST_NETWORK') != '1':
    raise SystemExit('Run through sandbox.py --net-admin; never on the host network')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    request = struct.pack('16sH14x', b'lo', 0)
    flags = struct.unpack('16sH14x', fcntl.ioctl(s, 0x8913, request))[1]
    fcntl.ioctl(s, 0x8914, struct.pack('16sH14x', b'lo', flags | 1))

def attribute(kind, value):
    b = struct.pack('HH', 4 + len(value), kind) + value
    return b + b'\0' * (-len(b) % 4)

with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as s:
    s.bind((0, 0))
    for seq, destination in enumerate(('192.0.2.0', '198.51.100.0', '203.0.113.0'), 1):
        route = struct.pack('BBBBBBBBI', socket.AF_INET, 24, 0, 0, 254, 4, 253, 1, 0)
        route += attribute(1, socket.inet_aton(destination))
        route += attribute(4, struct.pack('I', socket.if_nametoindex('lo')))
        s.send(struct.pack('IHHII', 16 + len(route), 24, 0x605, seq, 0) + route)
        response = s.recv(4096)
        error = struct.unpack_from('i', response, 16)[0]
        if error:
            raise OSError(-error, 'TEST-NET route setup failed')
if len(sys.argv) < 2:
    raise SystemExit('missing test command')
os.execvp(sys.argv[1], sys.argv[1:])
