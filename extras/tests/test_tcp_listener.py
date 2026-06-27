#!/usr/bin/env python3
"""
test_tcp_listener.py -- Reusable TCP listener for DPI and trust tests.
Run on h2 (the receiver) via xterm:

    mininet> xterm h2
    h2# python3 tests/test_tcp_listener.py [port]

Accepts connections in a loop, prints received data, then waits for next.
Default port: 9000. Ctrl+C to stop.
"""

import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT))
s.listen(5)
print(f'[listener] Listening on 0.0.0.0:{PORT}  (Ctrl+C to stop)')

try:
    while True:
        conn, addr = s.accept()
        try:
            data = conn.recv(8192)
            preview = data[:120]
            print(f'[listener] {addr[0]}:{addr[1]} -> {len(data)} bytes: {preview}')
        except Exception as e:
            print(f'[listener] Error reading from {addr}: {e}')
        finally:
            conn.close()
except KeyboardInterrupt:
    print('\n[listener] Stopped.')
finally:
    s.close()
