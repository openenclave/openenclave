#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -o errexit

if [[ -z $SUBSCRIPTION_ID ]]; then echo "ERROR: Env variable SUBSCRIPTION_ID is not set"; exit 1; fi
if [[ -z $SERVICE_PRINCIPAL_ID ]]; then echo "ERROR: Env variable SERVICE_PRINCIPAL_ID is not set"; exit 1; fi
if [[ -z $SERVICE_PRINCIPAL_PASSWORD ]]; then echo "ERROR: Env variable SERVICE_PRINCIPAL_PASSWORD is not set"; exit 1; fi
if [[ -z $TENANT_ID ]]; then echo "ERROR: Env variable TENANT_ID is not set"; exit 1; fi
if [[ -z $REGION ]]; then echo "ERROR: Env variable REGION is not set"; exit 1; fi
if [[ -z $RESOURCE_GROUP ]]; then echo "ERROR: Env variable RESOURCE_GROUP is not set"; exit 1; fi
if [[ -z $VNET_SUBNET_ID ]]; then echo "ERROR: Env variable VNET_SUBNET_ID is not set"; exit 1; fi
if [[ -z $DNS_PREFIX ]]; then echo "ERROR: Env variable DNS_PREFIX is not set"; exit 1; fi

#
# Create the Azure ACC Kubernetes cluster via aks-engine
#
az login --service-principal -u "${SERVICE_PRINCIPAL_ID}" -p "${SERVICE_PRINCIPAL_PASSWORD}" --tenant "${TENANT_ID}" --output table
az account set --subscription "${SUBSCRIPTION_ID}"

KEY=$(az keyvault secret show --vault-name "oe-ci-test-kv" --name "id-rsa-oe-test-pub" | jq -r .value | base64 -d)
PASSWORD=$(az keyvault secret show --vault-name "oe-ci-test-kv" --name "windows-pwd" | jq -r .value)

export WINDOWS_ADMIN_PASSWORD="$PASSWORD"
export SSH_PUBLIC_KEY="$KEY"

TEMPLATE="acc-k8s-cluster-${REGION}.json"


DIR=$(dirname "$0")
cd "$DIR"
eval "cat << EOF
$(cat "$TEMPLATE")
EOF
" > aks-engine-template.json
aks-engine generate aks-engine-template.json
RG_EXISTS=$(az group exists --name "$RESOURCE_GROUP")
if [[ "$RG_EXISTS" = "false" ]]; then
   az group create --name "$RESOURCE_GROUP" --location "$REGION" --output table
fi
az group deployment create --name acc-k8s \
                          --resource-group ${RESOURCE_GROUP} \
                          --template-file _output/${DNS_PREFIX}/azuredeploy.json\
                          --parameters @_output/${DNS_PREFIX}/azuredeploy.parameters.json \
                          --output table

export KUBECONFIG=_output/${DNS_PREFIX}/kubeconfig/kubeconfig.${REGION}.json
kubectl get nodes
kubectl apply -f "admin-user.yml"

az keyvault secret set --vault-name "oe-ci-test-kv" --name "kubeconfig-${DNS_PREFIX}-${REGION}" --file ${KUBECONFIG} --description "${DNS_PREFIX}.${REGION}.cloudapp.azure.com Kubeconfig"

echo "KUBECONFIG file successfully uploaded to oe-ci-test-kv keyvault"
exit 0
