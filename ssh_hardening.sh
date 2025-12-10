#!/bin/bash

set -e

SSH_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.backup-$(date +%F-%T)"

echo "[+] Backing up sshd_config to $BACKUP"
cp $SSH_CONFIG $BACKUP

# === User Input ===
read -rp "Enter the username to configure SSH for: " TARGET_USER

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    echo "[!] User does not exist. Exiting."
    exit 1
fi

read -rp "Paste the PUBLIC SSH KEY you want to install: " PUBKEY
read -rp "Change SSH port? (y/n): " CHANGE_PORT
read -rp "Disable password authentication? (y/n): " DISABLE_PASS
read -rp "Disable root login? (y/n): " DISABLE_ROOT
read -rp "Disable X11 forwarding? (y/n): " DISABLE_X11

echo
echo "[+] Installing SSH key for $TARGET_USER..."

USER_HOME=$(eval echo "~$TARGET_USER")
SSH_DIR="$USER_HOME/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

# Create SSH folder with correct permissions
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown "$TARGET_USER":"$TARGET_USER" "$SSH_DIR"

# Write authorized keys
echo "$PUBKEY" > "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"
chown "$TARGET_USER":"$TARGET_USER" "$AUTH_KEYS"

echo "[+] SSH key successfully installed."

# === Apply Hardening ===

echo "[+] Updating SSH configuration..."

# Scoring system
SCORE=0
MAX_SCORE=5  # Update if you add more rules

if [[ "$DISABLE_ROOT" == "y" ]]; then
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' $SSH_CONFIG
    SCORE=$((SCORE+1))
fi

if [[ "$DISABLE_PASS" == "y" ]]; then
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' $SSH_CONFIG
    sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' $SSH_CONFIG
    SCORE=$((SCORE+1))
fi

if [[ "$CHANGE_PORT" == "y" ]]; then
    read -rp "Enter new SSH port: " NEW_PORT
    sed -i "s/^#*Port .*/Port $NEW_PORT/" $SSH_CONFIG
    SCORE=$((SCORE+1))
else
    NEW_PORT=22
fi

if [[ "$DISABLE_X11" == "y" ]]; then
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' $SSH_CONFIG
    SCORE=$((SCORE+1))
fi

# Always apply these
sed -i 's/^#*UseDNS.*/UseDNS no/' $SSH_CONFIG
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSH_CONFIG
echo "MaxAuthTries 3" >> $SSH_CONFIG
echo "LoginGraceTime 30" >> $SSH_CONFIG
SCORE=$((SCORE+1))

echo "[+] Restarting SSH service..."
systemctl restart sshd || systemctl restart ssh

echo
echo "====================================="
echo "        SSH HARDENING COMPLETE        "
echo "====================================="
echo " SSH Port: $NEW_PORT"
echo " Public Key Installed For: $TARGET_USER"
echo
echo " Security Score: $SCORE / $MAX_SCORE"
if [[ $SCORE -ge 4 ]]; then
    echo " Rating: 🔐 Strong Security"
elif [[ $SCORE -ge 3 ]]; then
    echo " Rating: 🟡 Moderate Security"
else
    echo " Rating: 🔴 Weak Security — consider enabling more options"
fi
echo "====================================="
echo "[!] Remember to reconnect using: ssh -p $NEW_PORT $TARGET_USER@your-server"
echo "====================================="
