#!/usr/bin/env python3
"""
test_dpi_payloads.py -- Send DPI test payloads over raw TCP sockets.
Run on h1 (the sender) via xterm AFTER starting the listener on h2:

    h2# python3 tests/test_tcp_listener.py 9000
    h1# python3 tests/test_dpi_payloads.py [target_ip] [port]

Each payload is sent on a NEW connection (new ephemeral source port = new
flow key), so a previous block won't affect the next test.

Default target: 10.0.0.2:9000
"""

import socket
import sys
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else '10.0.0.2'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

PAYLOADS = [
    ('SQL_INJECTION',
     b'GET /search?q=1 union select password from users HTTP/1.0\r\n\r\n'),

    ('XSS_SCRIPT_TAG',
     b'POST /comment HTTP/1.0\r\nContent-Length: 30\r\n\r\n<script>alert(1)</script>'),

    ('PATH_TRAVERSAL',
     b'GET /../../etc/passwd HTTP/1.0\r\n\r\n'),

    ('CMD_INJECTION',
     b'GET /api?cmd=test;cat /etc/shadow HTTP/1.0\r\n\r\n'),

    ('SHELLCODE_NOP_SLED',
     b'\x90' * 32 + b'\xcc'),

    ('CLEAN (should pass)',
     b'GET /index.html HTTP/1.0\r\nHost: example.com\r\n\r\n'),
]


def send_payload(name, data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET, PORT))
        s.send(data)
        s.close()
        print(f'  [{name}] sent {len(data)} bytes')
    except ConnectionRefusedError:
        print(f'  [{name}] FAILED -- connection refused (is the listener running on h2?)')
    except Exception as e:
        print(f'  [{name}] FAILED -- {e}')


def main():
    print(f'DPI payload sender -> {TARGET}:{PORT}')
    print(f'Sending {len(PAYLOADS)} payloads with 1s delay between each.\n')
    print('Check the GUI event log for DPI blocked messages after each send.')
    print('The last payload (CLEAN) should NOT trigger a block.\n')

    for name, data in PAYLOADS:
        send_payload(name, data)
        time.sleep(1)

    print('\nDone. Verify results in the GUI event log and stats.')


if __name__ == '__main__':
    main()
