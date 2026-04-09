#!/bin/bash
# ════════════════════════════════════════════════════════
#  SENTINEL — SSH Brute Force Attack Demo
#  Simulates: T1110.001 Brute Force: Password Guessing
# ════════════════════════════════════════════════════════

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

TARGET="${1:-localhost}"
VICTIM_USER="${2:-$(whoami)}"

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SENTINEL DEMO: SSH Brute Force Attack               ║"
echo "║  MITRE: T1110.001 — Credential Access               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${CYAN}[*] Target:${RESET} $TARGET"
echo -e "${CYAN}[*] Attacker:${RESET} External VM (simulated)"
echo -e "${CYAN}[*] Technique:${RESET} Dictionary-based password guessing"
echo ""
echo -e "${ORANGE}[PHASE 1] Reconnaissance — checking SSH port${RESET}"
echo -e "    Command: ${BOLD}nmap -sV -p 22 $TARGET${RESET}"
sleep 1
echo -e "    [simulated output] 22/tcp open  ssh  OpenSSH 9.x"
echo ""

echo -e "${ORANGE}[PHASE 2] Brute Force — sending failed login attempts${RESET}"
FAKE_USERS=("admin" "root" "ubuntu" "user" "test" "guest" "kali" "pi" "postgres" "oracle")
for user in "${FAKE_USERS[@]}"; do
    echo -e "    ${RED}[FAIL]${RESET} ssh ${user}@${TARGET} — Permission denied"
    # Generate actual auth log entries via ssh attempts
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes \
        -o PasswordAuthentication=no "${user}@${TARGET}" 2>/dev/null &
    sleep 0.4
done

echo ""
echo -e "${ORANGE}[PHASE 3] Success — valid credential found${RESET}"
echo -e "    ${GREEN}[SUCCESS]${RESET} ssh ${VICTIM_USER}@${TARGET} — Authenticated!"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes \
    "${VICTIM_USER}@${TARGET}" "echo SENTINEL_TEST_OK" 2>/dev/null || true

echo ""
echo -e "${GREEN}[+] Demo complete.${RESET}"
echo -e "${CYAN}[*] Expected detection:${RESET} SSH_BRUTE_FORCE / SSH_KEY_SPRAY"
echo -e "${CYAN}[*] Check dashboard:${RESET} http://localhost:5000"
