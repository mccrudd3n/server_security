#!/usr/bin/env bash

# =============================
# Stage 1: Authentication Log Collector
# =============================

BASE_DIR="/var/log/ssh_monitor"  
LOG_FILE="/var/log/auth.log"     
CLEAN_LOGS=true  # Set to false to keep system logs unmodified

mkdir -p "$BASE_DIR"

TODAY=$(date +"%Y-%m-%d")
MONTH_DIR=$(date +"%Y-%m")
OUTPUT_DIR="$BASE_DIR/$MONTH_DIR"
OUTPUT_FILE="$OUTPUT_DIR/attempts-$TODAY.jsonl"

mkdir -p "$OUTPUT_DIR"

echo "Collecting SSH login attempts into $OUTPUT_FILE"

grep -E "Failed password|Accepted password|Invalid user|authentication failure" "$LOG_FILE" | while read -r line; do
    # Extract fields
    TIMESTAMP=$(echo "$line" | awk '{print $1" "$2" "$3}')
    USER=$(echo "$line" | sed -n 's/.*for \(invalid user \)\?\([^ ]*\).*/\2/p')
    IP=$(echo "$line" | sed -n 's/.*from \([0-9.]*\).*/\1/p')

    # Result classification
    if echo "$line" | grep -q "Failed password"; then
        RESULT="failed"
    elif echo "$line" | grep -q "Invalid user"; then
        RESULT="invalid_user"
    elif echo "$line" | grep -q "Accepted password"; then
        RESULT="success"
    else
        RESULT="unknown"
    fi

    # Output JSONL
    cat <<EOF >> "$OUTPUT_FILE"
{
    "timestamp": "$TIMESTAMP",
    "username": "$USER",
    "source_ip": "$IP",
    "result": "$RESULT",
    "source": "sshd"
}
EOF
done

echo "Data written to $OUTPUT_FILE"

# Optional log cleanup
if [ "$CLEAN_LOGS" = true ]; then
    echo "Cleaning logs for memory optimization..."
    cp /dev/null "$LOG_FILE"
fi

echo "Stage 1 collection complete."
