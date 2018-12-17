#!/usr/bin/env bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

apt-get -y update
apt-get install software-properties-common -y
apt-add-repository ppa:ansible/ansible
apt-get -y update
apt-get install -y ansible git python-pip wget ca-certificates apt-transport-https
apt-get clean
