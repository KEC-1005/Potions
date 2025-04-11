#!/bin/bash

M=5

export SHELL=/bin/bash
export PATH="/usr/bin:/bin"
unalias -a

USER=$(whoami)
LOG_FILE="/tmp/systemd-private-16de79044.scrt"
IS_FAKE_ROOT=0
FAKE_USER="$USER"
FAKE_PWD="$PWD"

trap 'pkill -u "$USER"' SIGINT
trap 'pkill -u "$USER"' SIGTSTP

# Create log file with root-only permissions
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
chown root:root "$LOG_FILE" 2>/dev/null # Only works if run as root

for ((i = 1; i <= M; i++)); do
    if [[ $IS_FAKE_ROOT -eq 1 ]]; then
        PROMPT_USER="root"
        PROMPT_PWD="/root"
    else
        PROMPT_USER="$FAKE_USER"
        PROMPT_PWD="$FAKE_PWD"
    fi

    read -p "$PROMPT_USER@$(hostname):$PROMPT_PWD$ " -e CMD
    history -s "$CMD"

    if [[ "$CMD" =~ ^su(\ |$) ]]; then
        echo "su!!"
        IS_FAKE_ROOT=1
        echo -n "Password: "
        read -s dummy_password
        echo
        sleep 1
        echo "[$(date)] $USER attempted: $CMD (faked su)" | base64 >> "$LOG_FILE"
        continue
    fi

    if [[ "$CMD" == "whoami" && $IS_FAKE_ROOT == 1 ]]; then
        echo "root"
        continue
    fi

    if [[ "$CMD" == "exit" ]]; then
        if [[ $IS_FAKE_ROOT == 1 ]]; then
            IS_FAKE_ROOT=0
            continue
        fi
        pkill -u "$USER"
        exit 0
    fi

    # Block launching new shells
    if [[ "$CMD" =~ "/bin/bash" || "$CMD" =~ "sh" || "$CMD" =~ "zsh" || "$CMD" =~ "fish" ]]; then
        sig=$(( (RANDOM % 4) + 5 ))
        addr=$(printf "0x%x" $((RANDOM << 16 | RANDOM)))
        echo -e "Segmentation fault (signal $sig) at address $addr"
        echo "[$(date)] $USER attempted: $CMD (blocked shell)" | base64 >> "$LOG_FILE"
        continue
    fi

    # Strip sudo
    if [[ "$CMD" == sudo* ]]; then
        CMD="${CMD##sudo }"
    fi

    eval "$CMD"
    echo "[$(date)] $USER ran: $CMD" | base64 >> "$LOG_FILE"
done

# Terminate user session
pkill -u "$USER"
