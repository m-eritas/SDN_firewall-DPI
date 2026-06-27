#!/usr/bin/env python3
"""
test_arp_spoof.py -- Send a forged ARP reply to test spoof detection.
Run on h3 via xterm (requires root -- Mininet xterms run as root).

    # First, establish legitimate ARP binding:
    mininet> h1 ping -c 1 h2

    # Then run this from h3's xterm:
    h3# python3 tests/test_arp_spoof.py

This sends an ARP reply claiming h1's IP (10.0.0.1) with h3's MAC,
directed at h2. The controller should detect the MAC mismatch and
log an ARP spoof event.

If scapy is not available, a raw-socket fallback is used.
"""

import struct
import socket
import sys

SPOOFED_IP = '10.0.0.1'
SPOOFER_MAC = '00:00:00:00:00:03'
TARGET_IP = '10.0.0.2'
TARGET_MAC = '00:00:00:00:00:02'
IFACE = 'h3-eth0'


def mac_to_bytes(mac_str):
    return bytes(int(b, 16) for b in mac_str.split(':'))


def send_with_scapy():
    from scapy.all import ARP, Ether, sendp
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(
        op=2,
        psrc=SPOOFED_IP,
        hwsrc=SPOOFER_MAC,
        pdst=TARGET_IP,
        hwdst=TARGET_MAC,
    )
    sendp(pkt, iface=IFACE, verbose=False)
    print(f'[scapy] Spoofed ARP sent: {SPOOFED_IP} -> MAC {SPOOFER_MAC}')


def send_with_raw_socket():
    """Fallback if scapy is not installed."""
    ETH_P_ARP = 0x0806

    eth = mac_to_bytes('ff:ff:ff:ff:ff:ff') + mac_to_bytes(SPOOFER_MAC) + struct.pack('!H', ETH_P_ARP)

    arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2)
    arp += mac_to_bytes(SPOOFER_MAC)
    arp += socket.inet_aton(SPOOFED_IP)
    arp += mac_to_bytes(TARGET_MAC)
    arp += socket.inet_aton(TARGET_IP)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    s.bind((IFACE, 0))
    s.send(eth + arp)
    s.close()
    print(f'[raw] Spoofed ARP sent: {SPOOFED_IP} -> MAC {SPOOFER_MAC}')


def main():
    print(f'ARP spoof test: claiming {SPOOFED_IP} with MAC {SPOOFER_MAC}')
    print(f'IMPORTANT: run "h1 ping -c 1 h2" first to establish legitimate binding.\n')

    try:
        send_with_scapy()
    except ImportError:
        print('scapy not found, using raw socket fallback.')
        try:
            send_with_raw_socket()
        except PermissionError:
            print('FAILED -- requires root (run from Mininet xterm)')
            sys.exit(1)

    print('\nCheck the GUI for "ARP spoof: 10.0.0.1" in the event log.')
    print('Check flows: mininet> sh ovs-ofctl dump-flows s1')
    print('Expected: priority=200 drop flow for arp,arp_spa=10.0.0.1')


if __name__ == '__main__':
    main()
