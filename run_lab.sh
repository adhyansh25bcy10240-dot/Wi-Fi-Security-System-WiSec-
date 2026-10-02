#!/bin/bash
set -e

PROJECT_DIR="/home/asus/projects/wifi-scanner"
VENV_PYTHON="/home/asus/projects/.venv/bin/python"

echo "=========================================================="
echo "🚀 REPRODUCIBLE NIDS ENVIRONMENT INITIALIZATION & TESTING"
echo "=========================================================="

# Check docker compose command variant
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    DOCKER_COMPOSE_CMD="docker compose"
fi

# 1. Environment Cleanup & Setup
echo "[*] Restarting Docker Containers & Isolated Bridge Network..."
cd $PROJECT_DIR
$DOCKER_COMPOSE_CMD down --remove-orphans > /dev/null 2>&1 || true
$DOCKER_COMPOSE_CMD up -d

# 2. Extract Docker Bridge Interface Name dynamically
BRIDGE_ID=$(docker network inspect lab_net -f '{{.Id}}' 2>/dev/null | cut -c1-12 || echo "3b14d142cadc")
FULL_IFACE="br-${BRIDGE_ID}"

if [ -z "$BRIDGE_ID" ]; then
    # Fallback search if network prefix differs
    BRIDGE_ID=$(docker network ls --filter name=nids_bridge -q | head -n 1 | xargs docker network inspect -f '{{.Id}}' | cut -c1-12)
fi

FULL_IFACE="br-${BRIDGE_ID}"

echo "[+] Target Container Running at 10.5.0.10:80"
echo "[+] Detected Isolated Network Interface: ${FULL_IFACE}"
echo "----------------------------------------------------------"

# 3. Execution Menu
echo "Select Action for Professor Demo:"
echo "1) Start Live Interactive Sniffer (Terminal UI)"
echo "2) Run Automated Multi-Vector Benchmark & Export Results"
read -p "Choice [1/2]: " choice

if [ "$choice" == "1" ]; then
    echo "[*] Launching Live AI Sniffer on ${FULL_IFACE}..."
    sudo $VENV_PYTHON $PROJECT_DIR/ai/live_ai_sniffer.py $FULL_IFACE
elif [ "$choice" == "2" ]; then
    echo "[*] Starting Live Sniffer in background..."
    sudo $VENV_PYTHON $PROJECT_DIR/ai/live_ai_sniffer.py $FULL_IFACE > /tmp/sniffer_bench.log 2>&1 &
    SNIFFER_PID=$!
    
    sleep 3
    echo "[*] Executing Simultaneous Attack Vector Tests..."
    sudo $VENV_PYTHON $PROJECT_DIR/ai/simultaneous_attack_test.py
    
    echo "[*] Waiting for evaluation window (5s)..."
    sleep 6
    
    echo "[*] Stopping Sniffer background process..."
    sudo kill -2 $SNIFFER_PID || true
    
    echo "[*] Generating Benchmark Metrics..."
    $VENV_PYTHON $PROJECT_DIR/ai/benchmark_evaluator.py
    
    echo "=========================================================="
    echo "✅ AUTOMATED BENCHMARK COMPLETE"
    echo "📁 Report Saved: $PROJECT_DIR/nids_benchmark_report.json"
    echo "=========================================================="
fi