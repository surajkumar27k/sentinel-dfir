#!/bin/bash
# ════════════════════════════════════════════════════════
#  SENTINEL — Lateral Movement Demo
#  Simulates: T1021.004 SSH, T1046 Network Scan
# ════════════════════════════════════════════════════════

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

TARGET_RANGE="${1:-192.168.1.0/24}"

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SENTINEL DEMO: Lateral Movement                     ║"
echo "║  MITRE: T1021.004 / T1046 — Lateral Movement        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${ORANGE}[1/3] Internal Network Scan — T1046${RESET}"
echo -e "    Command: ${BOLD}nmap -sn ${TARGET_RANGE}${RESET}"
echo "    [simulated] Scanning ${TARGET_RANGE}..."
for i in 1 2 3 4 5; do
    echo "    Host: 192.168.1.${i} up (latency 0.${i}ms)"
    sleep 0.3
done
sleep 1

echo ""
echo -e "${ORANGE}[2/3] SSH Pivot to Internal Host — T1021.004${RESET}"
echo -e "    Command: ${BOLD}ssh -J jump_host user@192.168.1.10${RESET}"
ssh -o ConnectTimeout=2 -o BatchMode=yes user@192.168.1.10 2>/dev/null &
sleep 1
echo -e "    Connection attempt to internal host logged"

echo ""
echo -e "${ORANGE}[3/3] Proxychains Tunnel Setup${RESET}"
echo -e "    Command: ${BOLD}proxychains nmap -sT 10.0.0.0/24${RESET}"
echo -e "    (proxychains binary execution detected by process monitor)"
which proxychains 2>/dev/null && proxychains echo test 2>/dev/null || echo "    [simulated] proxychains command spawned"
sleep 1

echo ""
echo -e "${GREEN}[+] Lateral movement demo complete.${RESET}"
echo -e "${CYAN}[*] Expected detections:${RESET} PORT_SCAN, SSH_LATERAL_MOVEMENT"
