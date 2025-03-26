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
    if [[ "$EUID" -ne 0 ]]; then
        SUDO=sudo
    fi
    ${SUDO} apt-get "${@}"
}

wait-apt-get update
wait-apt-get install -y lsb-release

# Check for a supported python3 version that is already installed.
# For Ansible Community vs. Ansible-core versions
# see https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html
# For Python version compatibility with Ansible versions
# see https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html#support-life
if [ "$(lsb_release -cs)" == "focal" ]; then
    # Ubuntu 20.04 has up to Python 3.9 available through official channels
    # Python 3.9 - 3.11 (Controller) is supported for Ansible 8 or Ansible-core 2.15
    SUPPORTED_PYTHON_VERSIONS=("3.11" "3.10" "3.9")
elif [ "$(lsb_release -cs)" == "jammy" ]; then
    # Ubuntu 22.04 has up to Python 3.10 available through official channels
    # Python 3.10 - 3.12 (Controller) is supported for Ansible 9 or Ansible-core 2.16
    SUPPORTED_PYTHON_VERSIONS=("3.12" "3.11" "3.10")
else
    echo "ERROR: Unsupported distribution. Open Enclave SDK requires Ubuntu 20.04 or 22.04."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d " " -f 2 | cut -d "." -f 1,2)
echo "Your Python3 version is ${PYTHON_VERSION}"
for version in "${SUPPORTED_PYTHON_VERSIONS[@]}"; do
    if [[ "$PYTHON_VERSION" == "$version" ]]; then
        PYTHON_EXECUTABLE="python${PYTHON_VERSION}"
        echo "Python version $PYTHON_VERSION is supported and will be used to install Ansible."
        break
    fi
done

# Install a supported Python version if it is not already installed.
wait-apt-get update
for version in "${SUPPORTED_PYTHON_VERSIONS[@]}"; do
    if apt-cache show "^python${version}$" > /dev/null; then
        if command -v apt-get > /dev/null; then
            wait-apt-get install libssl-dev libffi-dev python3-pip "python${version}" -y
            PYTHON_EXECUTABLE="python${version}"
            echo "Python version $version was installed."
            break
        else
            echo "ERROR: No supported Python version was found and only these package managers are supported: apt"
            exit 1
        fi
    fi
done

if [[ -z ${PYTHON_EXECUTABLE+x} ]]; then
    echo "ERROR: No supported Python versions could be installed. Please check whether your system can support any of the following Python versions:"
    printf "Python %s\n" "${SUPPORTED_PYTHON_VERSIONS[@]}"
    exit 1
fi

if [ "$(lsb_release -cs)" == "focal" ]; then
    REQUIREMENTS_FILE="requirements-ubuntu2004.txt"
elif [ "$(lsb_release -cs)" == "jammy" ]; then
    REQUIREMENTS_FILE="requirements.txt"
else
    echo "ERROR: Unsupported distribution. Open Enclave SDK requires Ubuntu 20.04 or 22.04."
    exit 1
fi
${PYTHON_EXECUTABLE} -m pip install --upgrade pip
${PYTHON_EXECUTABLE} -m pip install -U -r "${DIR}/${REQUIREMENTS_FILE}"

ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.windows
ansible-galaxy collection install community.windows
ansible-galaxy collection install community.docker
ansible-galaxy collection list
ansible --version
