// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

OECI_LIB_VERSION = params.OECI_LIB_VERSION ?: "master"
library "OpenEnclaveJenkinsLibrary@${OECI_LIB_VERSION}"

GLOBAL_TIMEOUT_MINUTES = 240
AZURE_IMAGES_MAP = [
    // Mapping between shared gallery image definition name and
    // generated Azure managed image name
    "ubuntu-20.04":      "",
    "ubuntu-22.04":      "",
    "WS22-nonSGX-clang-11":   "",
    "WS22-SGX-DCAP-clang-11": "",
]

def update_production_azure_gallery_images(String image_name) {
    timeout(GLOBAL_TIMEOUT_MINUTES) {
        stage("Azure CLI Login") {
            withCredentials([
                    string(credentialsId: 'Jenkins-CI-Subscription-Id', variable: 'SUBSCRIPTION_ID'),
                    string(credentialsId: 'Jenkins-CI-Tenant-Id', variable: 'TENANT_ID')]) {
                sh '''#!/bin/bash
                    az login --identity
                    az account set -s ${SUBSCRIPTION_ID}
                '''
            }
        }
        stage("Update production Azure managed image: ${image_name}") {
            sh """
                SOURCE_ID=\$(az sig image-version show \
                    --resource-group ${params.RESOURCE_GROUP} \
                    --gallery-name "${params.E2E_IMAGES_GALLERY_NAME}" \
                    --gallery-image-definition "${image_name}" \
                    --gallery-image-version ${params.IMAGE_ID} \
                    | jq -r '.id')

                az sig image-version create \
                    --resource-group ${params.RESOURCE_GROUP} \
                    --gallery-name ${params.PRODUCTION_IMAGES_GALLERY_NAME} \
                    --gallery-image-definition ${image_name} \
                    --gallery-image-version ${params.IMAGE_VERSION} \
                    --managed-image \${SOURCE_ID} \
                    --target-regions ${params.REPLICATION_REGIONS.split(',').join(' ')} \
                    --replica-count 1
            """
        }
    }
}

def parallel_steps = [:]
AZURE_IMAGES_MAP.keySet().each {
    image_name -> parallel_steps["Update Azure gallery ${image_name} image"] = { update_production_azure_gallery_images(image_name) }
}

pipeline {
    agent {
        label globalvars.AGENTS_LABELS["acc-ubuntu-20.04-vanilla"]
    }
    options {
        timeout(time: 240, unit: 'MINUTES')
    }
    parameters {
        string(name: 'REPOSITORY_NAME', defaultValue: 'openenclave/openenclave', description: '[OPTIONAL] GitHub repository to checkout')
        string(name: 'BRANCH_NAME', defaultValue: 'master', description: '[OPTIONAL] The branch used to checkout the repository')
        string(name: 'RESOURCE_GROUP', defaultValue: 'jenkins-images', description: '[OPTIONAL] The resouce group containing the Azure images')
        string(name: 'IMAGE_ID', description: '[REQUIRED] The image id to promote from E2E to Production. E.g. 2021.12.0336')
        string(name: 'E2E_IMAGES_GALLERY_NAME', defaultValue: 'e2e_images', description: '[OPTIONAL] The Azure Shared Image Gallery for E2E Images')
        string(name: 'PRODUCTION_IMAGES_GALLERY_NAME', defaultValue: 'production_images', description: '[OPTIONAL] The Azure Shared Image Gallery for Production Images')
        string(name: 'IMAGE_VERSION', defaultValue: '${IMAGE_ID}', description: '[OPTIONAL] The version that the image should be tagged as in Production_Images')
        string(name: 'REPLICATION_REGIONS', defaultValue: 'westus,westeurope,eastus,uksouth,eastus2,canadacentral', description: '[OPTIONAL] Replication regions for the shared gallery images definitions (comma-separated)')
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: '[OPTIONAL] Version of OE Libraries to use')
    }
    stages {
        stage("Install Azure CLI") {
            steps {
                retry(10) {
                    sh """
                        sleep 5
                        ${helpers.WaitForAptLock()}
                        sudo apt-get update
                        sudo apt-get -y install ca-certificates curl apt-transport-https lsb-release gnupg
                        curl -sL https://packages.microsoft.com/keys/microsoft.asc |
                            gpg --dearmor |
                            sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null
                        AZ_REPO=\$(lsb_release -cs)
                        echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ \$AZ_REPO main" |
                            sudo tee /etc/apt/sources.list.d/azure-cli.list
                        ${helpers.WaitForAptLock()}
                        sudo apt-get update
                        sudo apt-get -y install azure-cli jq
                    """
                }
            }
        }
        stage("Promote images") {
            steps {
                script {
                    parallel parallel_steps
                }
            }
        }
    }
    post {
        always {
            sh """
                az logout || true
                az cache purge
                az account clear
            """
        }
    }
}
