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
        string(name: "AGENTS_LABEL", defaultValue: 'acc-ubuntu-18.04', description: "Label of the agent to use to run this job")
        booleanParam(name: "PUBLISH_DOCKER_HUB", defaultValue: false, description: "Publish container to OECITeam Docker Hub?")
        booleanParam(name: "TAG_LATEST", defaultValue: false, description: "Update the latest tag to the currently built DOCKER_TAG")
        booleanParam(name: "PUBLISH_VERSION_FILE", defaultValue: false, description: "Publish versioning information?")
    }
    environment {
        // Docker plugin cannot seem to use credentials from Azure Key Vault
        DOCKERHUB_REPO_CREDS = 'oeciteamdockerhub'
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
                                ../build.sh -v "${params.SGX_VERSION}" -u "18.04" -t "${TAG_BASE_IMAGE}"
                                ../build.sh -v "${params.SGX_VERSION}" -u "20.04" -t "${TAG_BASE_IMAGE}"
                            """
                        }
                    }
                }
                stage('Test Base') {
                    parallel {
                        stage("Test Base - 18.04") {
                            steps {
                                script {
                                    base_1804_image = docker.image("openenclave-base-ubuntu-18.04:${TAG_BASE_IMAGE}")
                                    base_1804_image.inside("--user root:root --cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket") {
                                        sh """
                                            apt update
                                            apt install -y build-essential open-enclave libssl-dev
                                        """
                                        helpers.TestSamplesCommand(false, "open-enclave")
                                    }
                                }
                            }
                        }
                        stage("Test Base - 20.04") {
                            steps {
                                script {
                                    base_2004_image = docker.image("openenclave-base-ubuntu-20.04:${TAG_BASE_IMAGE}")
                                    base_2004_image.inside("--user root:root --cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket") {
                                        sh """
                                            apt update
                                            apt install -y build-essential open-enclave libssl-dev
                                        """
                                        helpers.TestSamplesCommand(false, "open-enclave")
                                    }
                                }
                            }
                        }
                    }
                }
                stage('Push to internal repository') {
                    steps {
                        script {
                            docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                base_1804_image.push()
                                base_2004_image.push()
                                if ( params.TAG_LATEST ) {
                                    base_1804_image.push('latest')
                                    base_2004_image.push('latest')
                                }
                            }
                            sh "docker logout ${params.INTERNAL_REPO}"
                        }
                    }
                }
                stage("Push to Docker Hub") {
                    when {
                        expression {
                            return params.PUBLISH_DOCKER_HUB
                        }
                    }
                    steps {
                        script {
                            sh("docker tag openenclave-base-ubuntu-20.04:${TAG_BASE_IMAGE} oeciteam/openenclave-base-ubuntu-20.04:${TAG_BASE_IMAGE}")
                            sh("docker tag openenclave-base-ubuntu-18.04:${TAG_BASE_IMAGE} oeciteam/openenclave-base-ubuntu-18.04:${TAG_BASE_IMAGE}")
                            dockerhub_base_2004_image = docker.image("oeciteam/openenclave-base-ubuntu-20.04:${TAG_BASE_IMAGE}")
                            dockerhub_base_1804_image = docker.image("oeciteam/openenclave-base-ubuntu-18.04:${TAG_BASE_IMAGE}")
                            docker.withRegistry('', DOCKERHUB_REPO_CREDS) {
                                dockerhub_base_2004_image.push()
                                dockerhub_base_1804_image.push()
                                if ( params.TAG_LATEST ) {
                                    dockerhub_base_2004_image.push('latest')
                                    dockerhub_base_1804_image.push('latest')
                                }
                            }
                            sh "docker logout"
                        }
                    }
                }
            }
        }
        stage("Full CI/CD Image") {
            stages {
                stage("Build, Test, and Push") {
                    parallel {
                        stage("Ubuntu 18.04") {
                            steps {
                                script {
                                    buildArgs = common.dockerBuildArgs(
                                        "ubuntu_version=18.04",
                                        "devkits_uri=${params.DEVKITS_URI}"
                                    )
                                    oe1804 = common.dockerImage("oetools-18.04:${TAG_FULL_IMAGE}", LINUX_DOCKERFILE, "${buildArgs}")
                                    oe1804.inside("--user root:root \
                                                   --cap-add=SYS_PTRACE \
                                                   --device /dev/sgx:/dev/sgx \
                                                   --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket") {
                                        sh """
                                            apt update
                                            apt install -y build-essential open-enclave libssl-dev
                                        """
                                        helpers.TestSamplesCommand(false, "open-enclave")
                                    }
                                    docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                        common.exec_with_retry { oe1804.push() }
                                        if ( params.TAG_LATEST ) {
                                            common.exec_with_retry { oe1804.push('latest') }
                                        }
                                    }
                                }
                            }
                        }
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
                                                   --device /dev/sgx/provision:/dev/sgx/provision \
                                                   --device /dev/sgx/enclave:/dev/sgx/enclave \
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
                stage('Publish oetools') {
                    when {
                        expression {
                            return params.PUBLISH_DOCKER_HUB
                        }
                    }
                    steps {
                        script {
                            sh("docker tag oetools-20.04:${TAG_BASE_IMAGE} oeciteam/oetools-20.04:${TAG_BASE_IMAGE}")
                            sh("docker tag oetools-18.04:${TAG_BASE_IMAGE} oeciteam/oetools-18.04:${TAG_BASE_IMAGE}")
                            dockerhub_full_2004_image = docker.image("oeciteam/oetools-20.04:${TAG_BASE_IMAGE}")
                            dockerhub_full_1804_image = docker.image("oeciteam/oetools-18.04:${TAG_BASE_IMAGE}")
                            docker.withRegistry('', DOCKERHUB_REPO_CREDS) {
                                dockerhub_full_2004_image.push()
                                dockerhub_full_1804_image.push()
                                if ( params.TAG_LATEST ) {
                                    dockerhub_full_2004_image.push('latest')
                                    dockerhub_full_1804_image.push('latest')
                                }
                            }
                            sh "docker logout"
                        }
                    }
                }
            }
        }
        stage('Publish info') {
            when {
                expression {
                    return params.PUBLISH_VERSION_FILE
                }
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'github-oeciteam-user-pat',
                                 usernameVariable: 'GIT_USERNAME',
                                 passwordVariable: 'GIT_PASSWORD')]) {
                    script {
                        sh '''
                            git config --global user.email "${GIT_USERNAME}@microsoft.com"
                            git config --global user.name ${GIT_USERNAME}
                            git checkout --force "oeciteam/publish-docker"
                            git pull
                        '''
                        BASE_2004_PSW  = helpers.dockerGetAptPackageVersion("openenclave-base-ubuntu-20.04:${TAG_BASE_IMAGE}", "libsgx-enclave-common")
                        BASE_2004_DCAP = helpers.dockerGetAptPackageVersion("openenclave-base-ubuntu-20.04:${TAG_BASE_IMAGE}", "libsgx-ae-id-enclave")
                        BASE_1804_PSW  = helpers.dockerGetAptPackageVersion("openenclave-base-ubuntu-18.04:${TAG_BASE_IMAGE}", "libsgx-enclave-common")
                        BASE_1804_DCAP = helpers.dockerGetAptPackageVersion("openenclave-base-ubuntu-18.04:${TAG_BASE_IMAGE}", "libsgx-ae-id-enclave")
                        FULL_2004_PSW  = helpers.dockerGetAptPackageVersion("oetools-20.04:${TAG_FULL_IMAGE}", "libsgx-enclave-common")
                        FULL_2004_DCAP = helpers.dockerGetAptPackageVersion("oetools-20.04:${TAG_FULL_IMAGE}", "libsgx-ae-id-enclave")
                        FULL_1804_PSW  = helpers.dockerGetAptPackageVersion("oetools-18.04:${TAG_FULL_IMAGE}", "libsgx-enclave-common")
                        FULL_1804_DCAP = helpers.dockerGetAptPackageVersion("oetools-18.04:${TAG_FULL_IMAGE}", "libsgx-ae-id-enclave")
                        REPOSITORY = params.INTERNAL_REPO - ~"^https://"
                        sh """#!/bin/bash
                            OE_VERSION=\$(grep --max-count=1 --only-matching --perl-regexp 'v\\d+\\.\\d+\\.\\d+(?=_log)' CHANGELOG.md)
                            cat <<EOF >>DOCKER_IMAGES.md
| Base Ubuntu 20.04 | ${REPOSITORY}/openenclave-base-ubuntu-20.04:${TAG_BASE_IMAGE} | \${OE_VERSION} | ${BASE_2004_PSW} | ${BASE_2004_DCAP} |
| Base Ubuntu 18.04 | ${REPOSITORY}/openenclave-base-ubuntu-18.04:${TAG_BASE_IMAGE} | \${OE_VERSION} | ${BASE_1804_PSW} | ${BASE_1804_DCAP} |
| Full Ubuntu 20.04 | ${REPOSITORY}/oetools-20.04:${TAG_FULL_IMAGE} | \${OE_VERSION} | ${FULL_2004_PSW} | ${FULL_2004_DCAP} |
| Full Ubuntu 18.04 | ${REPOSITORY}/oetools-18.04:${TAG_FULL_IMAGE} | \${OE_VERSION} | ${FULL_1804_PSW} | ${FULL_1804_DCAP} |
EOF
                        """
                    }
                    sh '''
                        git add DOCKER_IMAGES.md
                        git commit -sm "Publish Docker Images"
                        git push --force https://${GIT_PASSWORD}@github.com/openenclave/openenclave.git HEAD:oeciteam/publish-docker
                    '''
                }
            }
        }
    }
}
