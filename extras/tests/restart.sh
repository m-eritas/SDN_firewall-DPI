#!/bin/bash
# restart.sh -- Clean restart of controller + mininet.
# Run from the project root directory.
#
# Usage:
#     bash tests/restart.sh
#
# This kills any running controller/mininet processes, cleans up
# OVS and mininet state, then starts both fresh.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "[restart] Stopping mininet..."
sudo mn -c 2>/dev/null || true

echo "[restart] Killing any running controller..."
pkill -f "python.*main.py" 2>/dev/null || true
pkill -f "ryu-manager" 2>/dev/null || true
sleep 1

echo "[restart] Ensuring openvswitch is running..."
sudo systemctl start openvswitch-switch

echo "[restart] Starting controller in background..."
source ./.venv/bin/activate
.venv/bin/python3 src/main.py &
CTRL_PID=$!
echo "[restart] Controller PID: $CTRL_PID"

# Wait for WSGI to be ready
echo "[restart] Waiting for controller to start..."
for i in $(seq 1 15); do
    if curl -s http://localhost:8080/firewall/stats > /dev/null 2>&1; then
        echo "[restart] Controller is ready."
        break
    fi
    sleep 1
done

echo "[restart] Starting mininet..."
echo "[restart] Run this in another terminal:"
echo ""
echo "    cd $SCRIPT_DIR"
echo "    source ./.venv/bin/activate"
echo "    sudo ./.venv/bin/mn --controller remote --mac --topo single,3"
echo ""
echo "[restart] To stop everything later:"
echo "    sudo mn -c && kill $CTRL_PID"
