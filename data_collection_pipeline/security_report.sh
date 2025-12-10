#!/bin/bash

# ================================================
# Stage 3 - Security Overview Report Generator
# ================================================

DELETE_LOGS=false
USE_STAGE1_DATA=true        # Uses collected JSONL if set to true
BASE_DIR="/var/log/ssh_monitor"
TODAY=$(date +%Y-%m-%d)

REPORT_FILE="/home/blackhole/Projects/Telegram/Server_Monitor_Bot/ssh_security_report.txt"
JSON_FILE="/home/blackhole/Projects/Telegram/Server_Monitor_Bot/security_actions.json"

# Optional flag
if [[ "$1" == "--delete-logs" ]]; then
    DELETE_LOGS=true
fi

echo "🔍 Generating SSH security overview for $TODAY..."
echo ""

# ==================================================
# Load data from Stage 1 JSONL (preferred)
# ==================================================
if [ "$USE_STAGE1_DATA" = true ]; then
    MONTH=$(date +%Y-%m)
    INPUT_FILE="${BASE_DIR}/${MONTH}/attempts-${TODAY}.jsonl"

    if [ ! -f "$INPUT_FILE" ]; then
        echo "⚠ No Stage 1 JSONL found for today, falling back to journalctl"
        USE_STAGE1_DATA=false
    fi
fi

# ==================================================
# Extract attempts from logs
# ==================================================

if [ "$USE_STAGE1_DATA" = true ]; then
    echo "Using Stage 1 JSONL dataset: $INPUT_FILE"

    MAP=$(cat "$INPUT_FILE" | jq -r '
        select(.result == "invalid_user" or .result == "failed") |
        "\(.source_ip) \(.username)"
    ')
else
    echo "Using journalctl live logs"
    MAP=$(sudo journalctl _COMM=sshd | \
        grep "Invalid user" | \
        sed -n 's/.*Invalid user \([^ ]*\) from \([^ ]*\).*/\2 \1/p')
fi

# Ensure we have something
if [ -z "$MAP" ]; then
    echo "No unauthorized attempts detected today."
    echo "{}" > "$JSON_FILE"
    exit 0
fi

# ==================================================
# Process data
# ==================================================
TOTAL_ATTEMPTS=0
declare -A IP_ATTEMPTS
declare -A IP_USERS

while read -r ip user; do
    TOTAL_ATTEMPTS=$((TOTAL_ATTEMPTS+1))
    IP_ATTEMPTS[$ip]=$((IP_ATTEMPTS[$ip]+1))
    if [[ -z "${IP_USERS[$ip]}" ]]; then
        IP_USERS[$ip]="$user"
    else
        IP_USERS[$ip]="${IP_USERS[$ip]}, $user"
    fi
done <<< "$MAP"

# ==================================================
# Security Score Calculation
# ==================================================
# Score ranges 0–100
# Heuristic:
#   + More failed attempts = lower score
#   + More unique IPs = lower score
#   + Repeated usernames = more suspicious

UNIQUE_IPS=${#IP_ATTEMPTS[@]}
COMMON_ATTACK_THRESHOLD=50

if (( TOTAL_ATTEMPTS < 50 )); then SCORE=90
elif (( TOTAL_ATTEMPTS < 200 )); then SCORE=75
elif (( TOTAL_ATTEMPTS < 500 )); then SCORE=55
elif (( TOTAL_ATTEMPTS < 1000 )); then SCORE=35
else SCORE=20
fi

if (( UNIQUE_IPS > 50 )); then SCORE=$(( SCORE - 10 )); fi
if (( UNIQUE_IPS > 200 )); then SCORE=$(( SCORE - 15 )); fi

if (( SCORE < 0 )); then SCORE=0; fi

# ==================================================
# Generate Text Report
# ==================================================
{
echo "SSH Security Overview - $TODAY"
echo "--------------------------------"
echo ""
echo "Summary"
echo "-------"
echo "Total unauthorized attempts: $TOTAL_ATTEMPTS"
echo "Unique attacking IPs: $UNIQUE_IPS"
echo "Security Score: $SCORE / 100"
echo ""

echo "Top 5 IPs"
echo "----------"

# Sort by attempt count
for ip in "${!IP_ATTEMPTS[@]}"; do
    echo "${IP_ATTEMPTS[$ip]} $ip"
done | sort -nr | head -5 | while read -r count ip; do
    echo "- $ip | attempts: $count | users: ${IP_USERS[$ip]}"
done

echo ""
echo "Interpretation"
echo "--------------"
if (( SCORE > 80 )); then
    echo "Your server is experiencing low hostile activity."
elif (( SCORE > 50 )); then
    echo "Moderate attack activity — remain vigilant."
else
    echo "High attack activity — sustained brute-force attempts detected."
fi

echo ""
echo "Recommended Actions"
echo "-------------------"
echo "- Ensure password authentication is disabled"
echo "- Use SSH keys"
echo "- Keep system packages updated"
echo "- Optionally geo-block hostile regions"
echo ""
} > "$REPORT_FILE"

echo "📄 Text report generated:"
echo "$REPORT_FILE"

# ==================================================
# Generate JSON Action File
# ==================================================
{
echo "{"
echo "  \"date\": \"$TODAY\","
echo "  \"total_attempts\": $TOTAL_ATTEMPTS,"
echo "  \"unique_ips\": $UNIQUE_IPS,"
echo "  \"security_score\": $SCORE,"
echo "  \"attack_details\": {"

FIRST=true
for ip in "${!IP_ATTEMPTS[@]}"; do
    if ! $FIRST; then echo ","; fi
    FIRST=false
    echo -n "    \"$ip\": {\"attempts\": ${IP_ATTEMPTS[$ip]}, \"usernames\": \"${IP_USERS[$ip]}\"}"
done

echo ""
echo "  }"
echo "}"
} > "$JSON_FILE"

echo "📄 JSON action file generated:"
echo "$JSON_FILE"

# ==================================================
# Optional log deletion
# ==================================================
if [ "$DELETE_LOGS" = true ]; then
    echo "🗑 Deleting SSH journal logs..."
    sudo journalctl --rotate
    sudo journalctl --vacuum-time=1s -u sshd
fi

exit 0
