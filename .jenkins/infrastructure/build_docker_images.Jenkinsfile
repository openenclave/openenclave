// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

GLOBAL_TIMEOUT_MINUTES = 240
OECI_LIB_VERSION = params.OECI_LIB_VERSION ?: "master"
library "OpenEnclaveJenkinsLibrary@${OECI_LIB_VERSION}"

pipeline {
    agent {
        label globalvars.AGENTS_LABELS["shared"]
    }
    parameters {
        string(name: "SGX_VERSION", description: "[REQUIRED] Intel SGX version to install (Ex: 2.15.100). For versions see: https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/")
        string(name: "REPOSITORY_NAME", defaultValue: "openenclave/openenclave", description: "GitHub repository to checkout")
        string(name: "BRANCH_NAME", defaultValue: "master", description: "The branch used to checkout the repository")
        string(name: "INTERNAL_REPO", defaultValue: "https://oejenkinscidockerregistry.azurecr.io", description: "Url for internal Docker repository")
        string(name: "DOCKER_TAG", defaultValue: "", description: "[OPTIONAL] Specify the tag for the new Docker images.")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
        string(name: "BASE_DOCKER_TAG", defaultValue: "", description: "[OPTIONAL] Specify the tag for the new Base Docker images.")
        string(name: "IMAGES_BUILD_LABEL", defaultValue: "acc-ubuntu-18.04", description: "Label of the agent to use to run Linux container builds")
        string(name: "WINDOWS_AGENTS_LABEL", defaultValue: "windows-nonsgx", description: "Label of the agent to use to run Windows container builds")
        booleanParam(name: "PUBLISH_DOCKER_HUB", defaultValue: false, description: "Publish container to OECITeam Docker Hub?")
        booleanParam(name: "TAG_LATEST", defaultValue: false, description: "Update the latest tag to the currently built DOCKER_TAG")
    }
    stages {
        stage('Set dynamic default parameters') {
            steps {
                script {
                    if ( ! params.DOCKER_TAG ) {
                        params.DOCKER_TAG = helpers.get_date(".") + ".${BUILD_NUMBER}"
                    }
                    if ( ! params.BASE_DOCKER_TAG ) {
                        params.BASE_DOCKER_TAG = helpers.get_date(".") + ".${BUILD_NUMBER}"
                    }
                }
            }
        }
        stage('Parallel') {
            parallel {
                stage("Build Windows Docker Containers") {
                    steps {
                        build job: '/Private/Infrastructure/Windows-Docker-Container-Build',
                            parameters: [
                                string(name: 'REPOSITORY_NAME', value: params.REPOSITORY_NAME),
                                string(name: 'BRANCH_NAME', value: params.BRANCH_NAME),
                                string(name: 'INTERNAL_REPO', value: params.INTERNAL_REPO),
                                string(name: 'DOCKER_TAG', value: params.DOCKER_TAG),
                                string(name: 'OECI_LIB_VERSION', value: params.OECI_LIB_VERSION),
                                string(name: 'AGENTS_LABEL', value: params.WINDOWS_IMAGES_BUILD_LABEL),
                                booleanParam(name: 'PUBLISH_DOCKER_HUB', value: params.PUBLISH_DOCKER_HUB),
                                booleanParam(name: 'TAG_LATEST', value: params.TAG_LATEST)
                            ]
                    }
                }
                stage("Build Linux Docker Containers") {
                    steps {
                        build job: '/Private/Infrastructure/Linux-Docker-Container-Build',
                            parameters: [
                                string(name: 'REPOSITORY_NAME', value: params.REPOSITORY_NAME),
                                string(name: 'BRANCH_NAME', value: params.BRANCH_NAME),
                                string(name: 'INTERNAL_REPO', value: params.INTERNAL_REPO),
                                string(name: 'DOCKER_TAG', value: params.DOCKER_TAG),
                                string(name: 'AGENTS_LABEL', value: params.WINDOWS_AGENTS_LABEL),
                                string(name: 'OECI_LIB_VERSION', value: OECI_LIB_VERSION),
                                string(name: 'SGX_VERSION', value: params.SGX_VERSION),
                                string(name: 'BASE_DOCKER_TAG', value: params.BASE_DOCKER_TAG),
                                booleanParam(name: 'PUBLISH_DOCKER_HUB', value: params.PUBLISH_DOCKER_HUB),
                                booleanParam(name: 'TAG_LATEST', value: params.TAG_LATEST)
                            ]
                    }
                }
            }
        }
    }
}
