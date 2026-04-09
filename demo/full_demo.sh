#!/bin/bash
# ════════════════════════════════════════════════════════
#  SENTINEL — Full Kill Chain Demo
#  Simulates complete APT attack sequence
# ════════════════════════════════════════════════════════

DEMO_DIR="$(dirname "$0")"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SENTINEL: FULL APT KILL CHAIN SIMULATION           ║"
echo "║  Phases: Recon → Initial Access → Persistence       ║"
echo "║          → Priv Esc → Exfil → Defense Evasion       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

phases=("ssh_bruteforce_demo.sh" "persistence_demo.sh" "privesc_demo.sh" "exfiltration_demo.sh" "defense_evasion_demo.sh")
names=("SSH Brute Force" "Persistence" "Privilege Escalation" "Exfiltration" "Defense Evasion")

for i in "${!phases[@]}"; do
    echo ""; echo "══ Phase $((i+1))/5: ${names[$i]} ══"
    bash "$DEMO_DIR/${phases[$i]}" 2>/dev/null
    sleep 3
done

echo ""
echo "✅ Full kill chain simulation complete."
echo "   Check SENTINEL dashboard for all incidents."
