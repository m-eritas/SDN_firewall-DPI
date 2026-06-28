#!/usr/bin/env python3
"""
test_trust_flow.py -- Generate traffic to trigger trust flow installation.
Run on h1 via xterm AFTER starting the listener on h2:

    h2# python3 tests/test_tcp_listener.py 8080
    h1# python3 tests/test_trust_flow.py [target_ip] [port]

Sends 10 messages on a single persistent TCP connection. Since TRUST_K=5,
the controller should install a priority-400 trust flow after packet 5.

Default target: 10.0.0.2:8080

After running, verify:
    mininet> sh ovs-ofctl dump-flows s1
    (look for priority=400 flows matching the 5-tuple)
"""

import socket
import sys
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else '10.0.0.2'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

def main():
    print(f'Trust flow test -> {TARGET}:{PORT}')
    print(f'Sending 10 messages on a persistent connection (TRUST_K=5).\n')

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, PORT))
        local_port = s.getsockname()[1]
        print(f'Connected from ephemeral port {local_port}')
    except ConnectionRefusedError:
        print('FAILED -- connection refused (is the listener running on h2?)')
        sys.exit(1)

    for i in range(10):
        msg = f'request {i}\n'.encode()
        try:
            s.send(msg)
            print(f'  sent packet {i + 1}/10')
        except BrokenPipeError:
            print(f'  connection closed by remote at packet {i + 1}')
            break
        time.sleep(0.3)

    s.close()
    print(f'\nDone. Verify trust flow in the switch:')
    print(f'  mininet> sh ovs-ofctl dump-flows s1')
    print(f'  (look for priority=400 matching proto=6, src_port={local_port})')
    print(f'\nGUI: "Trust Flows" stat should be >= 1.')

if __name__ == '__main__':
    main()
