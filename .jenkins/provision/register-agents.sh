#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -o errexit

if [[ -z $SUBSCRIPTION_ID ]]; then echo "ERROR: Env variable SUBSCRIPTION_ID is not set"; exit 1; fi
if [[ -z $SERVICE_PRINCIPAL_ID ]]; then echo "ERROR: Env variable SERVICE_PRINCIPAL_ID is not set"; exit 1; fi
if [[ -z $SERVICE_PRINCIPAL_PASSWORD ]]; then echo "ERROR: Env variable SERVICE_PRINCIPAL_PASSWORD is not set"; exit 1; fi
if [[ -z $TENANT_ID ]]; then echo "ERROR: Env variable TENANT_ID is not set"; exit 1; fi

if [[ -z $XENIAL_HOSTS ]] && [[ -z $BIONIC_HOSTS ]]; then echo "ERROR: No env variable for Ansible hosts is set (XENIAL_HOSTS, BIONIC_HOSTS)"; exit 1; fi
if [[ ! -z $XENIAL_HOSTS ]] && [[ -z $XENIAL_LABEL ]]; then echo "ERROR: Env variable XENIAL_LABEL is not set"; exit 1; fi
if [[ ! -z $BIONIC_HOSTS ]] && [[ -z $BIONIC_LABEL ]]; then echo "ERROR: Env variable BIONIC_LABEL is not set"; exit 1; fi
if [[ -z $JENKINS_URL ]]; then echo "ERROR: Env variable JENKINS_URL is not set"; exit 1; fi
if [[ -z $JENKINS_ADMIN_NAME ]]; then echo "ERROR: Env variable JENKINS_ADMIN_NAME is not set"; exit 1; fi
if [[ -z $JENKINS_ADMIN_PASSWORD ]]; then echo "ERROR: Env variable JENKINS_ADMIN_PASSWORD is not set"; exit 1; fi

DIR=$(dirname "$0")

#
# Register the Azure ACC VM to Jenkins via the Ansible scripts
#
ANSIBLE_DIR=$(realpath "$DIR/../../scripts/ansible")
cd "$ANSIBLE_DIR"

SSH_PRIVATE_KEY="id-rsa-oe-test"
az login --service-principal -u "${SERVICE_PRINCIPAL_ID}" -p "${SERVICE_PRINCIPAL_PASSWORD}" --tenant "${TENANT_ID}" --output table
az account set --subscription "${SUBSCRIPTION_ID}"
az keyvault secret show --vault-name "oe-ci-test-kv" --name "id-rsa-oe-test" | jq -r .value | base64 -d > $SSH_PRIVATE_KEY
chmod 600 $SSH_PRIVATE_KEY

generate_ansible_host_var_file() {
    local AGENT_HOSTNAME=$1
    local AGENT_LABEL=$2
    AGENT_NAME=$(echo "$AGENT_HOSTNAME" | cut -d '.' -f1)
    {
        echo "jenkins_agent_name: $AGENT_NAME"
        echo "jenkins_agent_label: $AGENT_LABEL"
        echo "jenkins_url: '$JENKINS_URL'"
        echo "jenkins_admin_name: '$JENKINS_ADMIN_NAME'"
        echo "jenkins_admin_password: '$JENKINS_ADMIN_PASSWORD'"
    } > "inventory/host_vars/$AGENT_HOSTNAME"
}

LINUX_AGENTS=()
if [[ ! -z $XENIAL_HOSTS ]]; then
    for HOST in $(echo "$XENIAL_HOSTS" | tr ',' '\n'); do
        generate_ansible_host_var_file "$HOST" "$XENIAL_LABEL"
        LINUX_AGENTS+=("$HOST")
    done
fi
if [[ ! -z $BIONIC_HOSTS ]]; then
    for HOST in $(echo "$BIONIC_HOSTS" | tr ',' '\n'); do
        generate_ansible_host_var_file "$HOST" "$BIONIC_LABEL"
        LINUX_AGENTS+=("$HOST")
    done
fi


echo "[linux-agents]" > inventory/hosts
for AGENT in "${LINUX_AGENTS[@]}"; do
    echo "$AGENT" >> inventory/hosts
done

export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook jenkins-agents-register.yml --extra-vars="ansible_ssh_private_key_file=$SSH_PRIVATE_KEY"
