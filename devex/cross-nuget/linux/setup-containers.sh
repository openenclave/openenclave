#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

configure_container() {
    CONTAINER_NAME=$1

    # Map the default user inside the LXC container to the current host user.
    lxc config set "$CONTAINER_NAME" raw.idmap 'both 1000 1000'

    # Pass the current host user's home directory into the container.
    lxc config device add "$CONTAINER_NAME" homedir disk source="$HOME" path="$HOME"

    # Tell AppArmor that this container is unconfined because the Ansible
    # playbooks require performing system calls such as mount() that AppArmor
    # blocks inside LXC containers by default.
    lxc config set "$CONTAINER_NAME" raw.lxc "lxc.apparmor.profile=unconfined"
}

# Initialize the two containers.
echo Initializing build containers...
lxc init ubuntu:16.04 oepkgxenial
lxc init ubuntu:18.04 oepkgbionic

# Configure them.
echo Configuring build containers...
configure_container oepkgxenial
configure_container oepkgbionic

# Start them.
echo Starting build containers...
lxc start oepkgxenial oepkgbionic

echo Done.
