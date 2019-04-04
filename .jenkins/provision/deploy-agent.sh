#!/usr/bin/env bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set -o errexit

if [[ -z $SUBSCRIPTION_ID ]]; then echo "ERROR: Env variable SUBSCRIPTION_ID is not set"; exit 1; fi
if [[ -z $SERVICE_PRINCIPAL_ID ]]; then echo "ERROR: Env variable SERVICE_PRINCIPAL_ID is not set"; exit 1; fi
if [[ -z $SERVICE_PRINCIPAL_PASSWORD ]]; then echo "ERROR: Env variable SERVICE_PRINCIPAL_PASSWORD is not set"; exit 1; fi
if [[ -z $TENANT_ID ]]; then echo "ERROR: Env variable TENANT_ID is not set"; exit 1; fi
if [[ -z $REGION ]]; then echo "ERROR: Env variable REGION is not set"; exit 1; fi
if [[ -z $RESOURCE_GROUP ]]; then echo "ERROR: Env variable RESOURCE_GROUP is not set"; exit 1; fi

if [[ -z $AGENT_NAME ]]; then echo "ERROR: Env variable AGENT_NAME is not set"; exit 1; fi
if [[ -z $VHD_URL ]]; then echo "ERROR: Env variable VHD_URL is not set"; exit 1; fi
if [[ "$AGENT_TYPE" != "xenial" ]] && [[ "$AGENT_TYPE" != "bionic" ]]; then
    echo "ERROR: Env variable AGENT_TYPE has the wrong value. The allowed values for the script are: xenial, bionic"
    exit 1
fi

check_open_port() {
    #
    # Checks with a timeout if a particular port (TCP or UDP) is open (nc tool is used for this)
    #
    local ADDRESS="$1"
    local PORT="$2"
    local TIMEOUT=900
    echo "Checking, with a timeout of $TIMEOUT seconds, if the port $PORT is open at the address: $ADDRESS"
    SECONDS=0
    while true; do
        if [[ $SECONDS -gt $TIMEOUT ]]; then
            echo "ERROR: Port $PORT didn't open at $ADDRESS within $TIMEOUT seconds"
            return 1
        fi
        if nc -w 5 -z "$ADDRESS" "$PORT" &>/dev/null; then
            break
        fi
        sleep 1
    done
    echo "Success: Port $PORT is open at the address $ADDRESS"
}

#
# Create the Azure ACC VM via oe-engine
#
az login --service-principal -u "${SERVICE_PRINCIPAL_ID}" -p "${SERVICE_PRINCIPAL_PASSWORD}" --tenant "${TENANT_ID}" --output table
az account set --subscription "${SUBSCRIPTION_ID}"

KEY=$(az keyvault secret show --vault-name "oe-ci-test-kv" --name "id-rsa-oe-test-pub" | jq -r .value | base64 -d)
export SSH_PUBLIC_KEY="$KEY"

DIR=$(dirname "$0")
cd "$DIR"
eval "cat << EOF
$(cat "templates/oe-engine/ubuntu-${AGENT_TYPE}.json")
EOF
" > oe-engine-template.json
oe-engine generate --api-model oe-engine-template.json
RG_EXISTS=$(az group exists --name "$RESOURCE_GROUP")
if [[ "$RG_EXISTS" = "false" ]]; then
    az group create --name "$RESOURCE_GROUP" --location "$REGION" --output table
fi
az group deployment create --name "$AGENT_NAME" \
                           --resource-group "$RESOURCE_GROUP" \
                           --template-file _output/azuredeploy.json \
                           --parameters @_output/azuredeploy.parameters.json \
                           --output table
az image delete --resource-group "$RESOURCE_GROUP" --name "CustomLinuxImage"
check_open_port "${AGENT_NAME}.${REGION}.cloudapp.azure.com" "22"
