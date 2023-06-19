// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

TAG_BASE_IMAGE = params.BASE_DOCKER_TAG ?: helpers.get_date(".") + "${BUILD_NUMBER}"
TAG_FULL_IMAGE = params.DOCKER_TAG ?: helpers.get_date(".") + "${BUILD_NUMBER}"

pipeline {
    agent {
        label globalvars.AGENTS_LABELS[params.AGENTS_LABEL]
    }
    options {
        timeout(time: 240, unit: 'MINUTES')
    }
    parameters {
        string(name: "SGX_VERSION", description: "Intel SGX version to install (Ex: 2.15.100). For versions see: https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/")
        string(name: "REPOSITORY_NAME", defaultValue: "openenclave/openenclave", description: "GitHub repository to checkout")
        string(name: "BRANCH_NAME", defaultValue: "master", description: "The branch used to checkout the repository")
        string(name: "DOCKER_TAG", defaultValue: "", description: "[OPTIONAL] Specify the tag for the new Docker images.")
        string(name: "BASE_DOCKER_TAG", defaultValue: "", description: "[OPTIONAL] Specify the tag for the new Base Docker images.")
        string(name: "INTERNAL_REPO", defaultValue: "https://oejenkinscidockerregistry.azurecr.io", description: "Url for internal Docker repository")
        string(name: "INTERNAL_REPO_CRED_ID", defaultValue: "oejenkinscidockerregistry", description: "Credential ID for internal Docker repository")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
        string(name: "DEVKITS_URI", defaultValue: 'https://oejenkins.blob.core.windows.net/oejenkins/OE-CI-devkits-d1634ce8.tar.gz', description: "Uri for downloading the OECI Devkit")
        string(name: "AGENTS_LABEL", defaultValue: 'acc-ubuntu-20.04', description: "Label of the agent to use to run this job")
        booleanParam(name: "TAG_LATEST", defaultValue: false, description: "Update the latest tag to the currently built DOCKER_TAG")
    }
    environment {
        // Docker plugin cannot seem to use credentials from Azure Key Vault
        BASE_DOCKERFILE_DIR = ".jenkins/infrastructure/docker/dockerfiles/linux/base/"
        LINUX_DOCKERFILE = ".jenkins/infrastructure/docker/dockerfiles/linux/Dockerfile"
    }
    stages {
        stage("Checkout") {
            steps {
                cleanWs()
                checkout([$class: 'GitSCM',
                    branches: [[name: BRANCH_NAME]],
                    extensions: [],
                    userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY_NAME}"]]])
            }
        }
        stage("Base Image") {
            stages {
                stage('Build Base') {
                    steps {
                        dir(env.BASE_DOCKERFILE_DIR) {
                            sh """
                                chmod +x ./build.sh
                                mkdir build
                                cd build
                                ../build.sh -v "${params.SGX_VERSION}" -u "20.04" -t "${TAG_BASE_IMAGE}"
                            """
                        }
                    }
                }
                stage("Test Base - 20.04") {
                    steps {
                        script {
                            base_2004_image = docker.image("openenclave-base-ubuntu-20.04:${TAG_BASE_IMAGE}")
                            base_2004_image.inside("--user root:root \
                                                    --cap-add=SYS_PTRACE \
                                                    --device /dev/sgx_enclave:/dev/sgx_enclave \
                                                    --device /dev/sgx_provision:/dev/sgx_provision \
                                                    --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket") {
                                sh """
                                    apt update
                                    apt install -y build-essential open-enclave libssl-dev curl
                                """
                                helpers.TestSamplesCommand(false, "open-enclave")
                            }
                        }
                    }
                }
                stage('Push to internal repository') {
                    steps {
                        script {
                            docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                base_2004_image.push()
                                if ( params.TAG_LATEST ) {
                                    base_2004_image.push('latest')
                                }
                            }
                            sh "docker logout ${params.INTERNAL_REPO}"
                        }
                    }
                }
            }
        }
        stage("Full CI/CD Image") {
            stages {
                stage("Ubuntu 20.04") {
                    steps {
                        script {
                            buildArgs = common.dockerBuildArgs(
                                "ubuntu_version=20.04",
                                "devkits_uri=${params.DEVKITS_URI}"
                            )
                            oe2004 = common.dockerImage("oetools-20.04:${TAG_FULL_IMAGE}", LINUX_DOCKERFILE, "${buildArgs}")
                            oe2004.inside("--user root:root \
                                           --cap-add=SYS_PTRACE \
                                           --device /dev/sgx_provision:/dev/sgx_provision \
                                           --device /dev/sgx_enclave:/dev/sgx_enclave \
                                           --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket") {
                                sh """
                                    apt update
                                    apt install -y build-essential open-enclave libssl-dev
                                """
                                helpers.TestSamplesCommand(false, "open-enclave")
                            }
                            docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                common.exec_with_retry { oe2004.push() }
                                if ( params.TAG_LATEST ) {
                                    common.exec_with_retry { oe2004.push('latest') }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
