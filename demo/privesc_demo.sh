#!/bin/bash
# ════════════════════════════════════════════════════════
#  SENTINEL — Privilege Escalation Demo
#  Simulates: T1548.003 Sudo Abuse, T1548.001 SUID
# ════════════════════════════════════════════════════════

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SENTINEL DEMO: Privilege Escalation                 ║"
echo "║  MITRE: T1548 — Privilege Escalation                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${ORANGE}[1/3] Sudo Abuse — T1548.003${RESET}"
echo -e "    Command: ${BOLD}sudo bash -i${RESET} (attacker spawns root shell via sudo)"
echo "sudo bash -i 2>/dev/null || echo '(permission denied — simulated)'" | bash 2>/dev/null || true
sleep 1

echo ""
echo -e "${ORANGE}[2/3] SUID Binary Enumeration — T1548.001${RESET}"
echo -e "    Command: ${BOLD}find / -perm -4000 -type f 2>/dev/null${RESET}"
find /usr -perm -4000 -type f 2>/dev/null | head -10
sleep 1

echo ""
echo -e "${ORANGE}[3/3] /etc/passwd Inspection — T1003.008${RESET}"
echo -e "    Command: ${BOLD}cat /etc/passwd | grep -v nologin${RESET}"
cat /etc/passwd | grep -v nologin | head -5
echo "    (credential file read detected by SENTINEL)"
sleep 1

echo ""
echo -e "${GREEN}[+] Privilege escalation demo complete.${RESET}"
echo -e "${CYAN}[*] Expected detections:${RESET} SUDO_ABUSE, SUID_ABUSE, PASSWD_FILE_ACCESS"
