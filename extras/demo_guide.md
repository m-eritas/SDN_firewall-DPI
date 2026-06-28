# Demo Guide -- SDN Firewall

This file has two parts: read the topology section once before the demo;
use the checklist section live, while running the demo.

---

## Part 1 -- Network topology (read before the demo)

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

```
                 +-------------------+
                 |   s1 (firewall)   |
                 +-------------------+
                  /        |        \
                 /         |         \
            h1 (PC)   h2 (server)   h3 (external)
           10.0.0.1    10.0.0.2      10.0.0.3
```

### Why this satisfies the "fake company network" requirement

The project spec asks for a fake company network with internal hosts
connected to "the Internet," filtered by one SDN switch acting as a
firewall. Architecturally, that's what's already running:

- `s1` is the single point of enforcement for every packet between any
  pair of hosts -- the same role a perimeter firewall plays between a LAN
  and a WAN.
- `h1` and `h2` represent the internal network (employee PC and the
  server it talks to). All DPI, trust-flow, and rate-limit tests run on
  this pair.
- `h3` plays the external/untrusted role: the ARP-spoof test
  (`test_arp_spoof.py`) sends its forged reply from `h3`, modeling an
  attacker outside the trusted segment trying to poison ARP state on the
  internal hosts.

No code change was needed to reflect this -- the controller enforces
firewall policy uniformly regardless of which host is labeled what, so
the "company network" requirement is met by the controller's design
(single enforcement point, policy applies to all traffic) rather than by
host naming or subnetting.

A custom `Topo` subclass with renamed hosts (`pc1`, `web_server`,
`internet_host`, etc.) was considered but not used, to avoid touching the
IPs/hostnames that all five test scripts in `extras/tests/` already
target by default. Keeping the default topology means every existing
test runs unmodified and the testing guide's commands stay accurate.

---

## Part 2 -- Live demo checklist (use during the demo)

Target: under 5 minutes. Covers one example of each required rule type:
static rule, dynamic detection, DPI, and a timed/auto-expiring rule.
Full test coverage with all edge cases lives in `extras/tests/testing_guide.md`
this is the condensed version for live presentation only.

**Before starting:** controller running (`src/main.py`), Mininet running
(`mn --controller remote --mac --topo single,3`), GUI open at
`http://localhost:8080/`.

### Step 1 -- Baseline connectivity

```
mininet> pingall
```
Expect: `0% dropped`. Shows the network is up before any rules are applied.

### Step 2 -- Static rule: block an IP

```bash
curl -s -X POST http://localhost:8080/firewall/rules/ip/10.0.0.3
```
```
mininet> h1 ping -c 3 10.0.0.3
```
Expect: 100% packet loss. GUI: "Blocked IPs" shows `10.0.0.3`, event log
shows `IP blocked: 10.0.0.3`. This demonstrates the static-rule
requirement (block by IP, persists until removed -- see "Known
limitations" in the README for why static rules don't auto-expire,
unlike the dynamic detections below).

Unblock to reset:
```bash
curl -s -X DELETE http://localhost:8080/firewall/rules/ip/10.0.0.3
```

### Step 3 -- Dynamic rule: DPI payload block

```
mininet> xterm h1 h2
```
On h2's xterm:
```bash
python3 extras/tests/test_tcp_listener.py 9000
```
On h1's xterm:
```bash
python3 extras/tests/test_dpi_payloads.py
```
Expect: GUI event log shows `DPI blocked [SQL_INJECTION]` and similar
entries for each malicious payload; the final CLEAN payload passes
through with no block. Demonstrates payload-level dynamic inspection,
distinct from the static IP/port rules above.

### Step 4 -- Timed/auto-expiring rule: trust flow

On h2's xterm (new listener, different port):
```bash
python3 extras/tests/test_tcp_listener.py 8080
```
On h1's xterm:
```bash
python3 extras/tests/test_trust_flow.py
```
```
mininet> sh ovs-ofctl dump-flows s1
```
Expect: priority=400 flow entries for the 5-tuple, with
`idle_timeout=60` and `hard_timeout=300` visible in the dump. This is the
example of a rule that auto-expires by design, contrasted with the
static IP block in Step 2.

### Step 5 -- GUI tour

With the GUI open, point out:
- Live event log (every step above appears here in real time over the
  WebSocket connection)
- Stat counters (Total, Allowed, Blocked, DPI Blocked, Trust Flows)
- DPI Patterns section (6 built-in signatures + ability to add one live
  via the REST API or GUI form)

### Reset between full runs

```bash
bash extras/tests/restart.sh
```
Clears all in-memory state (trust table, blocked flags, rate trackers)
and restarts the controller cleanly. Not required between the steps
above since they use different hosts/ports, but recommended before
repeating the full demo.
