#!/usr/bin/env bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

apt-get purge --auto-remove -y \
    ansible \
    python-pip \
    apt-transport-https \
    software-properties-common
