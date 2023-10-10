// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

import java.time.*
import java.time.format.DateTimeFormatter

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

GLOBAL_TIMEOUT_MINUTES = 240

OETOOLS_REPO_NAME = "oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"

IMAGE_ID = ""
NOW = LocalDateTime.now()
IMAGE_VERSION = NOW.format(DateTimeFormatter.ofPattern("yyyy")) + "." + \
                NOW.format(DateTimeFormatter.ofPattern("MM")) + "." + \
                NOW.format(DateTimeFormatter.ofPattern("dd")) + env.BUILD_NUMBER
DOCKER_TAG = "e2e-${IMAGE_VERSION}-${BUILD_NUMBER}"


pipeline {
    agent any
    options {
        timeout(time: 8, unit: 'HOURS')
    }
    parameters {
        string(name: 'REPOSITORY', defaultValue: 'openenclave/openenclave', description: 'GitHub owner/repository', trim: true)
        string(name: 'BRANCH', defaultValue: 'master', description: "GitHub repository branch to checkout", trim: true)
        string(name: 'SGX_VERSION', defaultValue: '', description: "[Required] For Docker containers only. Choose the Intel SGX version to install (Ex: 2.15.100). For versions see: https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files", trim: true)
        string(name: 'RESOURCE_GROUP', defaultValue: 'jenkins-images', description: "The resource group name used for the creation of Azure managed images", trim: true)
        string(name: 'E2E_IMAGES_GALLERY_NAME', defaultValue: 'e2e_images', description: "E2E Azure images gallery name", trim: true)
        string(name: 'PRODUCTION_IMAGES_GALLERY_NAME', defaultValue: '', description: "[OPTIONAL]: Specify the Azure Shared Image Gallery for storing production images", trim: true)
        string(name: 'REPLICATION_REGIONS', defaultValue: 'westeurope,eastus,uksouth,eastus2,westus,canadacentral', description: '[OPTIONAL] Replication regions for the shared gallery images definitions (comma-separated)', trim: true)
        string(name: 'UBUNTU_2004_CFL_LABEL', defaultValue: 'e2e-ACC-2004', description: 'Label to use for image testing and promotion', trim: true)
        string(name: 'UBUNTU_2004_ICX_LABEL', defaultValue: 'e2e-ACC-2004-v3', description: 'Label to use for image testing and promotion', trim: true)
        string(name: 'UBUNTU_NONSGX_LABEL', defaultValue: 'e2e-nonSGX-ubuntu-2004', description: 'Label to use for image testing and promotion', trim: true)
        string(name: 'WINDOWS_2019_DCAP_CFL_LABEL', defaultValue: 'e2e-SGXFLC-Windows-2019-DCAP', description: 'Label to use for image testing and promotion', trim: true)
        string(name: 'WINDOWS_2019_DCAP_ICX_LABEL', defaultValue: 'e2e-SGXFLC-Windows-2019-DCAP-v3', description: 'Label to use for image testing and promotion', trim: true)
        string(name: 'WINDOWS_NONSGX_CUSTOM_LABEL', defaultValue: 'e2e-nonsgx-windows', description: 'Label to use for image testing and promotion', trim: true)
        string(name: 'IMAGES_BUILD_LABEL', defaultValue: 'vanilla-ubuntu-2004', description: 'Agent label used to run Azure Managed Image builds', trim: true)
        string(name: 'OECI_LIB_VERSION', defaultValue: 'master', description: 'Version of OE Libraries to use', trim: true)
    }
    stages {
        stage("Build Docker Containers") {
            steps {
                build job: '/Private/Infrastructure/OpenEnclave-Build-Docker-Images',
                    parameters: [
                        string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                        string(name: 'BRANCH_NAME', value: env.BRANCH),
                        string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                        string(name: 'BASE_DOCKER_TAG', value: DOCKER_TAG),
                        string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                        string(name: 'SGX_VERSION', value: params.SGX_VERSION),
                        booleanParam(name: 'TAG_LATEST', value: false),
                        booleanParam(name: 'PUBLISH', value: false)
                    ]
            }
        }
        stage("Determine IMAGE_ID") {
            steps {
                cleanWs()
                checkout scm
                script {
                    last_commit_id = sh(script: "git rev-parse --short HEAD", returnStdout: true).tokenize().last()
                    IMAGE_ID = IMAGE_VERSION + "-" + last_commit_id
                }
                println("IMAGE_ID: ${IMAGE_ID}")
                println("IMAGE_VERSION: ${IMAGE_VERSION}")
                println("DOCKER_TAG: ${DOCKER_TAG}")
            }
        }
        stage("Build Jenkins Agents Images") {
            steps {
                build job: '/Private/Infrastructure/OpenEnclave-Build-Azure-Managed-Images',
                    parameters: [
                        string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                        string(name: 'BRANCH_NAME', value: env.BRANCH),
                        string(name: 'OE_DEPLOY_IMAGE', value: "oetools-20.04:${DOCKER_TAG}"),
                        string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                        string(name: 'RESOURCE_GROUP', value: env.RESOURCE_GROUP),
                        string(name: 'GALLERY_NAME', value: env.E2E_IMAGES_GALLERY_NAME),
                        string(name: 'REPLICATION_REGIONS', value: env.REPLICATION_REGIONS),
                        string(name: 'IMAGE_ID', value: IMAGE_ID),
                        string(name: 'IMAGE_VERSION', value: IMAGE_VERSION),
                        string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                        string(name: 'AGENTS_LABEL', value: env.IMAGES_BUILD_LABEL)
                    ]
            }
        }
        stage("Run tests on new Agents") {
            steps {
            build job: '/Private/OpenEnclave/OpenEnclave-Testing',
                parameters: [
                    string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                    string(name: 'BRANCH_NAME', value: env.BRANCH),
                    string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                    string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                    string(name: 'UBUNTU_2004_CFL_CUSTOM_LABEL', value: params.UBUNTU_2004_CFL_LABEL),
                    string(name: 'UBUNTU_2004_ICX_CUSTOM_LABEL', value: params.UBUNTU_2004_ICX_LABEL),
                    string(name: 'UBUNTU_2004_NONSGX_LABEL', value: params.UBUNTU_NONSGX_LABEL),
                    string(name: 'WS2019_DCAP_CFL_LABEL', value: params.WINDOWS_2019_DCAP_LABEL),
                    string(name: 'WS2019_DCAP_ICX_LABEL', value: params.WINDOWS_2019_DCAP_LABEL),
                    string(name: 'WINDOWS_NONSGX_CUSTOM_LABEL', value: params.WINDOWS_NONSGX_CUSTOM_LABEL),
                    booleanParam(name: 'FULL_TEST_SUITE', value: true),
                    booleanParam(name: 'FORCE_TEST', value: true)
                ]
            }
        }
        stage("Update production infrastructure") {
            when { 
                expression { return params.PRODUCTION_IMAGES_GALLERY_NAME != "" }
            }
            steps {
                build job: '/Private/Infrastructure/OpenEnclave-Update-Production-Infrastructure',
                    parameters: [
                        string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                        string(name: 'BRANCH_NAME', value: env.BRANCH),
                        string(name: 'RESOURCE_GROUP', value: env.RESOURCE_GROUP),
                        string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                        string(name: 'PRODUCTION_IMAGES_GALLERY_NAME', value: env.PRODUCTION_IMAGES_GALLERY_NAME),
                        string(name: 'REPLICATION_REGIONS', value: env.REPLICATION_REGIONS),
                        string(name: 'IMAGE_ID', value: IMAGE_ID),
                        string(name: 'IMAGE_VERSION', value: IMAGE_VERSION),
                        string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                        string(name: 'IMAGES_BUILD_LABEL', value: env.UBUNTU_2004_LABEL)
                    ]
            }
        }
    }
}
