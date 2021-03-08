#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -o errexit

DIR=$(dirname "$0")

function wait-apt-get {
    i=0
    echo "Checking for locks..."
    # Check for locks
    while fuser /var/lib/dpkg/lock > /dev/null 2>&1 ||
          fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1 ||
          fuser /var/lib/apt/lists/lock > /dev/null 2>&1; do
        # Wait up to 600 seconds to lock to be released
        if (( i > 600 )); then
            echo "Timeout waiting for lock."
            exit 1
        fi
        echo "Waiting for apt/dpkg locks..."
        i=$((i++))
        sleep 1
    done
    apt-get "${@}"
}

if which yum > /dev/null; then
    yum install git python3-pip -y
elif which apt-get > /dev/null; then
    wait-apt-get update
    wait-apt-get install libssl-dev libffi-dev python3-pip -y
else
    echo "ERROR: Only these package managers are supported: yum, apt-get"
    exit 1
fi

pip3 install -U -r "$DIR/requirements.txt"
