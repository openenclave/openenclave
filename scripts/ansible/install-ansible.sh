#!/usr/bin/env bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set -o errexit

DIR=$(dirname "$0")

apt-get update
apt-get install libssl-dev libffi-dev python3-pip -y
pip3 install -U -r "$DIR/requirements.txt"
