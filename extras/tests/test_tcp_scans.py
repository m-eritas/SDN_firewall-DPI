#!/usr/bin/env python3
"""
test_tcp_scans.py -- Send TCP packets with suspicious flag combinations.
Run on h1 via xterm (requires root -- Mininet xterms run as root).

    h1# python3 tests/test_tcp_scans.py [target_ip]

Default target: 10.0.0.2
Sends: XMAS, NULL, SYN+FIN, SYN+RST, FIN-only, and a legitimate SYN.
Check the GUI for scan detection events after running.
"""

import socket
import struct
import sys
import time

SRC_IP = '10.0.0.1'
DST_IP = sys.argv[1] if len(sys.argv) > 1 else '10.0.0.2'
SRC_PORT = 12345
DST_PORT = 80

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
URG = 0x20

SCANS = [
    ('XMAS  (FIN+PSH+URG)',  FIN | PSH | URG,  True),
    ('NULL  (no flags)',      0x00,              True),
    ('SYN+FIN',              SYN | FIN,         True),
    ('SYN+RST',              SYN | RST,         True),
    ('FIN only',             FIN,               True),
    ('SYN only (legitimate)', SYN,              False),
]


def send_tcp_flags(flags_byte):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, 54321, 0x4000, 64, 6, 0,
        socket.inet_aton(SRC_IP), socket.inet_aton(DST_IP))

    tcp_header = struct.pack('!HHIIBBHHH',
        SRC_PORT, DST_PORT, 0, 0, 0x50, flags_byte, 1024, 0, 0)

    s.sendto(ip_header + tcp_header, (DST_IP, 0))
    s.close()


def main():
    print(f'TCP scan test -> {DST_IP}:{DST_PORT}')
    print(f'Sending {len(SCANS)} packets with 0.5s delay.\n')

    for name, flags, should_detect in SCANS:
        try:
            send_tcp_flags(flags)
            expect = 'should trigger scan warning' if should_detect else 'should NOT trigger warning'
            print(f'  [{name}]  flags=0x{flags:02x}  sent  ({expect})')
        except PermissionError:
            print(f'  [{name}]  FAILED -- requires root (run from Mininet xterm)')
            return
        except Exception as e:
            print(f'  [{name}]  FAILED -- {e}')
        time.sleep(0.5)

    print('\nDone. Check the GUI event log for scan detection messages.')
    print('The last packet (SYN only) should NOT appear as a scan.')


if __name__ == '__main__':
    main()
