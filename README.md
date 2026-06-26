# SDN_firewall
Basic SDN Firewall implemented with Ryu and tested with Mininet. Local-only web page as Network Switch Controller GUI.


## Installation & Usage
> Tested on Acer with i5-10210U, 16GB RAM, 512GB SSD — Ubuntu 24.04.3 LTS (and Linux Mint 22.2), kernel 6.17.0-14-generic

## Features

- **IP blocking** — block traffic by source IP, with input validation
- **Port blocking** — block TCP/UDP by port number and protocol
- **Rate limiting** — configurable packet-per-window threshold per source IP; exceeded sources get a temporary hardware drop rule
- **ARP spoof detection** — learns legitimate IP→MAC bindings and drops forged ARP replies
- **TCP scan detection** — identifies XMAS, NULL, SYN+FIN, SYN+RST, and bare FIN scans via flag inspection
- **Deep packet inspection** — regex-based payload matching on TCP streams with 6 built-in signatures (SQL injection, shellcode NOP sled, XSS, path traversal, command injection, FTP cleartext credentials) and support for user-defined patterns via REST
- **Trust flow installation** — after K clean packets on a 5-tuple, installs a priority-400 hardware forwarding rule so trusted traffic bypasses the controller. Adding a new DPI pattern flushes all trust flows for re-inspection
- **Web GUI** — dark-themed dashboard with live WebSocket event log, stat counters, and controls for all rule types
- **REST API** — full CRUD for IPs, ports, rate limits, and DPI patterns

## Project structure

```
src/                          <- project source code
   main.py                    <- entry point (rewrites argv, calls ryu-manager)
   firewall_app.py            <- Ryu app: packet logic, all firewall state
   firewall_wsgi.py           <- REST API + WebSocket handler
   dpi_engine.py              <- standalone regex-based payload matcher
   gui/
      firewall_gui.html       <- single-page dashboard
vendor/                       <- patched third-party forks (not project code)
   ryu/                       <- Ryu controller (patched for Python 3.12)
   mininet/                   <- Mininet (patched for Python 3.12)

docs/                         <- testing guide, notes
   testing_guide.md
README.md
LICENSE
.gitignore
```

### Install & Run
```bash
# global libraries
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y git xterm python3-pip python3.12 python3.12-venv python3.12-dev python3-pip openvswitch-switch

# project istallation
git clone https://github.com/GioeleSe/SDN_firewall/
cd SDN_firewall

# local libraries (from patched source)
source ./.venv/bin/activate
 ./.venv/bin/python3 -m pip install ./ryu/
 ./.venv/bin/python3 -m pip install ./mininet/
make ./mininet/mnexec
sudo install -v ./mininet/mnexec /usr/local/bin/

# project start
sudo systemctl start openvswitch-switch # enable ovs as background service 
.venv/bin/python3 main.py	# on one terminal start the controller app
sudo ./.venv/bin/mn --controller remote --mac --topo single,3 # on the other terminal start mininet
```
Open `http://localhost:8080/` for the GUI.

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/firewall/rules` | All rules (IPs, ports, rate config) |
| POST | `/firewall/rules/ip/{ip}` | Block a source IP |
| DELETE | `/firewall/rules/ip/{ip}` | Unblock a source IP |
| POST | `/firewall/rules/port/{port}/{proto}` | Block a port (proto: 6=TCP, 17=UDP) |
| DELETE | `/firewall/rules/port/{port}/{proto}` | Unblock a port |
| POST | `/firewall/rules/ratelimit` | Set rate limit (JSON body: `{limit, window}`) |
| GET | `/firewall/dpi` | List all DPI patterns |
| POST | `/firewall/dpi` | Add pattern (JSON body: `{name, pattern, description}`) |
| DELETE | `/firewall/dpi/{name}` | Remove a user-defined pattern |
| GET | `/firewall/stats` | Traffic counters |
| GET | `/firewall/log` | Last 100 event log entries |

## Known limitations

- **DPI inspects only during trust-building.** Once a trust flow is installed (after 5 clean packets), subsequent traffic on that 5-tuple goes directly through the switch hardware and is never seen by the controller or DPI engine. Adding a new DPI pattern flushes all trust flows to mitigate this.
- **No authentication on the REST API.** Anyone who can reach port 8080 can modify firewall rules. Acceptable for a lab environment, not for production.
- **Source-only IP blocking.** The `blocked_ips` rule checks `ip_src` only. Bidirectional protocols like ICMP ping appear fully blocked because the reply (sourced from the blocked IP) is dropped.
- **ReDoS heuristic is not exhaustive.** User-submitted DPI patterns are checked against a regex blocklist for common backtracking constructs, but adversarial patterns like `(a|a)+b` can still slip through.

### Uninstall
```bash
# stopping the project
Ctrl+C                            # to stop the (foreground) process of the server (and the mininet on the other terminal)
deactivate                       # exit from the python virtual environment
sudo systemctl stop openvswitch-switch    # stop the background service

# uninstalling the project:	
cd .. && sudo rm -rf SDN_firewall
```

---
*The development was done cooperating with Claude - AI agent of Anthropic.
The agent decision was taken after seeing the company's stance against the massive use of AI for what's somehow called security but has been correctly defined as mass surveillance. I believe that the company's courage in questioning the military use of AI in the most controversial areas should be recognized, despite the other company's  implications. The CEO's statement is available at https://www.anthropic.com/news/statement-department-of-war*
> There was no vibe-coding behind it but a slow and steady reading of papers and docs to understand the logic of libraries and protocols involved. <br>
> The agent has been used to produce a first GUI schema and, in general, for the most lengthy sections. <br>
> The entire code has been (and will be) checked and revised. <br>
> No gray area o spaghetti code will be left (and if so, it will be caused only by our code skill-issue problem)

## License

Apache-2.0
