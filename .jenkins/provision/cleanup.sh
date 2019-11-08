#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -o errexit

if [[ -z $SUBSCRIPTION_ID ]]; then echo "ERROR: Env variable SUBSCRIPTION_ID is not set"; exit 1; fi
if [[ -z $SERVICE_PRINCIPAL_ID ]]; then echo "ERROR: Env variable SERVICE_PRINCIPAL_ID is not set"; exit 1; fi
if [[ -z $SERVICE_PRINCIPAL_PASSWORD ]]; then echo "ERROR: Env variable SERVICE_PRINCIPAL_PASSWORD is not set"; exit 1; fi
if [[ -z $TENANT_ID ]]; then echo "ERROR: Env variable TENANT_ID is not set"; exit 1; fi
if [[ -z $RESOURCE_GROUP ]]; then echo "ERROR: Env variable RESOURCE_GROUP is not set"; exit 1; fi

az login --service-principal -u "${SERVICE_PRINCIPAL_ID}" -p "${SERVICE_PRINCIPAL_PASSWORD}" --tenant "${TENANT_ID}" --output table
az account set --subscription "${SUBSCRIPTION_ID}"
RG_EXISTS=$(az group exists --name "$RESOURCE_GROUP")
if [[ "$RG_EXISTS" = "true" ]]; then
    az group delete --name "${RESOURCE_GROUP}" --yes --no-wait
fi
