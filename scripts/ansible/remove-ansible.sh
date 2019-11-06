#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -o errexit

DIR=$(dirname "$0")

apt-get update
apt-get install python3-pip -y
pip3 uninstall -r "$DIR/requirements.txt" -y
