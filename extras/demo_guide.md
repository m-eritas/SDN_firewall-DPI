# Demo Guide -- SDN Firewall

## Network topology

This project uses Mininet's default `single,3` topology (one switch, three
hosts, `10.0.0.0/8`). No custom topology script is used: the existing
hosts are given company roles here for context, and the same `h1`/`h2`/`h3`
names and `10.0.0.1`-`10.0.0.3` addresses are used unchanged by every test
script in `extras/tests/`.

### Role mapping

| Mininet host | IP        | Company role                                  |
|---------------|-----------|------------------------------------------------|
| `h1`          | 10.0.0.1  | Internal PC (employee workstation)             |
| `h2`          | 10.0.0.2  | Internal server (web/DB, target of DPI tests)  |
| `h3`          | 10.0.0.3  | External / untrusted host (simulated Internet) |

## Live demo checklist

**Ensure before starting:** controller running (`src/main.py`), Mininet running
(`mn --controller remote --mac --topo single,3`), GUI open at
`http://localhost:8080/`.

### Step 1 - Baseline connectivity

```
mininet>
pingall
```
Expected: `0% dropped`.

Showcases the network is up before any rules are applied.

### Step 2 - Static rule: block an IP

```bash
curl -s -X POST http://localhost:8080/firewall/rules/ip/10.0.0.3
mininet>
h1 ping -c 3 10.0.0.3
```
Expected: `100% dropped`, GUI: "Blocked IPs" shows `10.0.0.3`, event log shows `IP blocked: 10.0.0.3`. 

Showcases the static-rule requirement, as the IP is blocked and persists until removed.

Unblock to reset:
```bash
curl -s -X DELETE http://localhost:8080/firewall/rules/ip/10.0.0.3
```

### Step 3 - Dynamic rule: DPI payload block

```
mininet>
xterm h1 h2

h2>
python3 extras/tests/test_tcp_listener.py 9000

h1>
python3 extras/tests/test_dpi_payloads.py
```

Expected: GUI event log shows `DPI blocked [SQL_INJECTION]` and similar entries for each malicious payload; the final CLEAN payload passes through with no block. 

Showcases payload-level dynamic inspection, distinct from the static IP/port rules above.

### Step 4 - Timed/auto-expiring rule: trust flow

```
h2>
python3 extras/tests/test_tcp_listener.py 8080

h1>
python3 extras/tests/test_trust_flow.py

mininet>
sh ovs-ofctl dump-flows s1
```

Expected: priority=400 flow entries for the 5-tuple, with `idle_timeout=60` and `hard_timeout=300` visible in the dump. 

Showcases that flow rules auto-expire by design.

### Step 5 - GUI tour

GUI avalable at `http://localhost:8080/` includes:
- Live event log (every step above appears here in real time over the WebSocket connection)
- Stat counters (Total, Allowed, Blocked, DPI Blocked, Trust Flows)
- DPI Patterns section (6 built-in signatures + ability to add one live via the REST API or GUI form)

### Reset between full runs

```bash
bash extras/tests/restart.sh
```
Clears all in-memory state (trust table, blocked flags, rate trackers) and restarts the controller cleanly. Not required between the steps above since they use different hosts/ports, but recommended before repeating the full demo or carrying out other tests availalable in /extras/tests or personal.
