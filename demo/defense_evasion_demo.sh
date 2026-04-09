#!/bin/bash
# ════════════════════════════════════════════════════════
#  SENTINEL — Defense Evasion Demo
#  Simulates: T1070 Log Clearing, T1036 Masquerading
# ════════════════════════════════════════════════════════

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SENTINEL DEMO: Defense Evasion                      ║"
echo "║  MITRE: T1070 / T1036 — Defense Evasion             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${ORANGE}[1/3] History Clearing — T1070.003${RESET}"
echo -e "    Command: ${BOLD}history -c && unset HISTFILE${RESET}"
bash -c 'history -c; echo "history cleared"'
bash -c 'HISTFILE=/dev/null; echo "HISTFILE disabled"'
sleep 1

echo ""
echo -e "${ORANGE}[2/3] Log Tampering Attempt — T1070.002${RESET}"
echo -e "    Command: ${BOLD}echo '' > /var/log/auth.log${RESET}"
echo -e "    (attempting to clear auth log — will be blocked/detected)"
bash -c 'echo "" > /var/log/auth.log 2>/dev/null || echo "    [blocked] — no write permission (expected)"'
sleep 1

echo ""
echo -e "${ORANGE}[3/3] Binary Masquerading — T1036.005${RESET}"
echo -e "    Command: ${BOLD}cp /bin/bash /tmp/systemd-helper${RESET}"
cp /bin/bash /tmp/systemd-helper 2>/dev/null || cp /bin/sh /tmp/systemd-helper
echo -e "    ${RED}[CREATED]${RESET} /tmp/systemd-helper (disguised shell)"
sleep 1
rm -f /tmp/systemd-helper
echo -e "    ${GREEN}[CLEANED]${RESET} Removed"

echo ""
echo -e "${GREEN}[+] Defense evasion demo complete.${RESET}"
echo -e "${CYAN}[*] Expected detections:${RESET} HISTORY_CLEAR, LOG_TAMPERING, BINARY_MASQUERADING"
