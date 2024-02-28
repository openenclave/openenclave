#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -o errexit

DIR=$(dirname "$0")

if [[ -d ~/.ansible/collections/ansible_collections/community/general ]]; then
    echo "Removing community.general from Ansible collections..."
    rm -rf ~/.ansible/collections/ansible_collections/community/general
fi
if [[ -d ~/.ansible/collections/ansible_collections/ansible/windows ]]; then
    echo "Removing ansiblle.windows from Ansible collections..."
    rm -rf ~/.ansible/collections/ansible_collections/ansible/windows
fi
if [[ -d ~/.ansible/collections/ansible_collections/community/windows ]]; then
    echo "Removing community.windows from Ansible collections..."
    rm -rf ~/.ansible/collections/ansible_collections/community/windows
fi
if ! command -v ansible; then
    echo "No Ansible installation found!"
fi

# Get Python version from Ansible in PATH
PYTHON_VERSION=$(ansible --version | grep "python version" | awk '{print $4}' | cut -d "." -f 1,2)
PYTHON_EXECUTABLE=python${PYTHON_VERSION}

if [[ -z ${PYTHON_VERSION+x} ]]; then
    echo "ERROR: The Python version from Ansible could not be found! Found version: ${PYTHON_VERSION}"
fi

${PYTHON_EXECUTABLE} -m pip uninstall -r "$DIR/requirements.txt" -y
