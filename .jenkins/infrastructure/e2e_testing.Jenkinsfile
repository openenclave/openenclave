// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

import java.time.*
import java.time.format.DateTimeFormatter

OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

GLOBAL_TIMEOUT_MINUTES = 240

OETOOLS_REPO_NAME = "oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"

IMAGE_ID = ""
NOW = LocalDateTime.now()
IMAGE_VERSION = NOW.format(DateTimeFormatter.ofPattern("yyyy")) + "." + \
                NOW.format(DateTimeFormatter.ofPattern("MM")) + "." + \
                NOW.format(DateTimeFormatter.ofPattern("dd"))
DOCKER_TAG = "e2e-${IMAGE_VERSION}-${BUILD_NUMBER}"


node(env.IMAGES_BUILD_LABEL) {
    stage("Determine the Azure managed images id") {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            cleanWs()
            checkout scm
            def last_commit_id = sh(script: "git rev-parse --short HEAD", returnStdout: true).tokenize().last()
            IMAGE_ID = IMAGE_VERSION + "-" + last_commit_id
        }
    }
}

println("IMAGE_ID: ${IMAGE_ID}")
println("IMAGE_VERSION: ${IMAGE_VERSION}")
println("DOCKER_TAG: ${DOCKER_TAG}")

stage("Build Docker Images") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Build-Docker-Images',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                       string(name: 'AGENTS_LABEL', value: env.IMAGES_BUILD_LABEL),
                       string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                       booleanParam(name: 'TAG_LATEST',value: false)]
}

stage("Build Jenkins Agents images") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Build-Azure-Managed-Images',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${DOCKER_TAG}"),
                       string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                       string(name: 'RESOURCE_GROUP', value: env.RESOURCE_GROUP),
                       string(name: 'GALLERY_NAME', value: env.E2E_IMAGES_GALLERY_NAME),
                       string(name: 'REPLICATION_REGIONS', value: env.REPLICATION_REGIONS),
                       string(name: 'IMAGE_ID', value: IMAGE_ID),
                       string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                       string(name: 'AGENTS_LABEL', value: env.IMAGES_BUILD_LABEL)]
}

stage("Run tests on new Agents") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Testing',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                       string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                       string(name: 'UBUNTU_1604_CUSTOM_LABEL', value: env.UBUNTU_1604_LABEL),
                       string(name: 'UBUNTU_1804_CUSTOM_LABEL', value: env.UBUNTU_1804_LABEL),
                       string(name: 'UBUNTU_NONSGX_CUSTOM_LABEL', value: env.UBUNTU_NONSGX_LABEL),
                       string(name: 'RHEL_8_CUSTOM_LABEL', value: env.RHEL_8_LABEL),
                       string(name: 'WINDOWS_2016_CUSTOM_LABEL', value: env.WINDOWS_2016_LABEL),
                       string(name: 'WINDOWS_2016_DCAP_CUSTOM_LABEL', value: env.WINDOWS_2016_DCAP_LABEL),
                       string(name: 'WINDOWS_2019_CUSTOM_LABEL', value: env.WINDOWS_2019_LABEL),
                       string(name: 'WINDOWS_2019_DCAP_CUSTOM_LABEL', value: env.WINDOWS_2019_DCAP_LABEL),
                       string(name: 'WINDOWS_NONSGX_CUSTOM_LABEL', value: env.WINDOWS_NONSGX_LABEL),
                       booleanParam(name: 'FULL_TEST_SUITE', value: true)]
}

if(env.PRODUCTION_IMAGES_GALLERY_NAME) {
    stage("Update production infrastructure") {
        build job: '/CI-CD_Infrastructure/OpenEnclave-Update-Production-Infrastructure',
            parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                         string(name: 'BRANCH_NAME', value: env.BRANCH),
                         string(name: 'RESOURCE_GROUP', value: env.RESOURCE_GROUP),
                         string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                         string(name: 'PRODUCTION_IMAGES_GALLERY_NAME', value: env.PRODUCTION_IMAGES_GALLERY_NAME),
                         string(name: 'REPLICATION_REGIONS', value: env.REPLICATION_REGIONS),
                         string(name: 'IMAGE_ID', value: IMAGE_ID),
                         string(name: 'IMAGE_VERSION', value: IMAGE_VERSION),
                         string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                         string(name: 'IMAGES_BUILD_LABEL', value: env.UBUNTU_1604_LABEL)]
    }
}
