#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -o errexit

DIR=$(dirname "$0")

if command -v yum > /dev/null; then
    yum install python3-pip -y
elif command -v apt-get > /dev/null; then
    apt-get update
    apt-get install python3-pip -y
else
    echo "ERROR: Only these package managers are supported: yum, apt-get"
    exit 1
fi

pip3 uninstall -r "$DIR/requirements.txt" -y
