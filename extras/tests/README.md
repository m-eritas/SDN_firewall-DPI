# Test Scripts

Standalone test scripts for the SDN firewall. Each script tests one feature group.

## Prerequisites

- Controller running: `.venv/bin/python3 src/main.py`
- Mininet running: `sudo ./.venv/bin/mn --controller remote --mac --topo single,3`
- **Restart both** between test groups to reset in-memory state.

## Test order

DPI tests must run before trust tests on the same host pair. Once trust is installed, packets bypass the controller and DPI never sees them.

Recommended order:

1. `test_rest_api.py` (no Mininet needed)
2. `bash tests/restart.sh` + start mininet
3. `test_tcp_scans.py`
4. Restart
5. `test_arp_spoof.py`
6. Restart
7. `test_dpi_payloads.py`
8. Restart
9. `test_trust_flow.py`

## Scripts

### restart.sh -> Clean restart

Kills controller/mininet, runs `sudo mn -c`, restarts the controller:

```bash
bash extras/tests/restart.sh
```

Then start mininet manually in a second terminal (the script prints the command).

### test_rest_api.py -> REST API validation (no Mininet required)

Tests all endpoints, input validation, and edge cases. Run from any terminal:

```bash
python3 extras/tests/test_rest_api.py
```

### test_dpi_payloads.py -> DPI signature detection

Sends 5 malicious payloads + 1 clean payload over TCP. Run the listener on h2 first, then the sender on h1:

```
mininet>
xterm h1 h2

h2 xterm>
python3 extras/tests/test_tcp_listener.py 9000

h1 xterm>
python3 extras/tests/test_dpi_payloads.py
```

Check the GUI event log for `DPI blocked [PATTERN_NAME]` entries. The last payload (CLEAN) should NOT trigger a block.

### test_tcp_scans.py -> TCP flag scan detection

Sends packets with suspicious TCP flag combinations (XMAS, NULL, SYN+FIN, SYN+RST, FIN, and a legitimate SYN):

```
mininet>
xterm h1

h1 xterm>
python3 extras/tests/test_tcp_scans.py
```

Check the GUI for scan detection events. The last packet (SYN only) should not trigger a warning.

### test_arp_spoof.py -> ARP spoof detection

Sends a forged ARP reply from h3 claiming h1's IP. Must establish a legitimate ARP binding first:

```
mininet>
h1 ping -c 1 h2
mininet>
xterm h3

h3 xterm>
python3 extras/tests/test_arp_spoof.py
```

Check the GUI for `ARP spoof: 10.0.0.1` and verify the drop flow with `sh ovs-ofctl dump-flows s1`.

### test_trust_flow.py -> Trust flow installation

Sends 10 messages on a persistent TCP connection to exceed TRUST_K=5:

```
mininet>
xterm h1 h2

h2 xterm>
python3 extras/tests/test_tcp_listener.py 8080

h1 xterm>
python3 extras/tests/test_trust_flow.py
```

Verify the priority-400 trust flows: `mininet> sh ovs-ofctl dump-flows s1`.

### test_tcp_listener.py -> Reusable TCP listener

Helper script used by the DPI and trust tests. Run on h2 to accept and display incoming connections:

```bash
python3 extras/tests/test_tcp_listener.py [port]
# default: 9000
```
