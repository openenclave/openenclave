#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Install LXD.
echo Installing LXD...
sudo apt install lxd

# Initialize LXD (the defaults are fine).
echo Starting LXD initialization...
echo You may accept the defaults.
sudo lxd init

# Add the current user to the 'lxd' group.
echo Adding "$USER" to lxd group...
sudo usermod -aG lxd "$USER"

# Allow mapping the default user inside the LXC containers to the current host
# user.
echo Enabling user mapping...
echo root:$UID:1 | sudo tee -a /etc/subuid /etc/subgid

echo Done.
