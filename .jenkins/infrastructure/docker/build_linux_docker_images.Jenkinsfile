// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

pipeline {
    agent {
        label globalvars.AGENTS_LABELS["acc-ubuntu-18.04"]
    }
    options {
        timeout(time: 240, unit: 'MINUTES')
    }
    parameters {
        string(name: "SGX_VERSION", description: "Intel SGX version to install (Ex: 2.15.100). For versions see: https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/")
        string(name: "REPOSITORY_NAME", defaultValue: "openenclave/openenclave", description: "GitHub repository to checkout")
        string(name: "BRANCH_NAME", defaultValue: "master", description: "The branch used to checkout the repository")
        string(name: "DOCKER_TAG", defaultValue: "standalone-linux-build", description: "The tag for the new Docker images")
        string(name: "INTERNAL_REPO", defaultValue: "https://oejenkinscidockerregistry.azurecr.io", description: "Url for internal Docker repository")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
        booleanParam(name: "PUBLISH_DOCKER_HUB", defaultValue: false, description: "Publish container to OECITeam Docker Hub?")
        booleanParam(name: "TAG_LATEST", defaultValue: false, description: "Update the latest tag to the currently built DOCKER_TAG")
    }
    environment {
        INTERNAL_REPO_CREDS = 'oejenkinscidockerregistry'
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
                                ../build.sh -v "${params.SGX_VERSION}" -u "18.04" -t "${params.DOCKER_TAG}"
                                ../build.sh -v "${params.SGX_VERSION}" -u "20.04" -t "${params.DOCKER_TAG}"
                            """
                        }
                    }
                }
                stage('Test Base') {
                    parallel {
                        stage("Test Base - 18.04") {
                            steps {
                                script {
                                    def image = docker.image("openenclave-bionic:${params.DOCKER_TAG}")
                                    image.inside("--user root:root --cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket") {
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
                                    def image = docker.image("openenclave-focal:${params.DOCKER_TAG}")
                                    image.inside("--user root:root --cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket") {
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
            }
        }
        stage("Full CI/CD Image") {
            parallel {
                stage("Build Ubuntu 18.04 Docker Image") {
                    steps {
                        script {
                            oe1804 = common.dockerImage("oetools-18.04:${DOCKER_TAG}", LINUX_DOCKERFILE, "--build-arg ubuntu_version=18.04")
                            puboe1804 = common.dockerImage("oeciteam/oetools-18.04:${DOCKER_TAG}", LINUX_DOCKERFILE, "--build-arg ubuntu_version=18.04")
                        }
                    }
                }
                stage("Build Ubuntu 20.04 Docker Image") {
                    steps {
                        script {
                            oe2004 = common.dockerImage("oetools-20.04:${DOCKER_TAG}",LINUX_DOCKERFILE, "--build-arg ubuntu_version=20.04")
                            puboe2004 = common.dockerImage("oeciteam/oetools-20.04:${DOCKER_TAG}", LINUX_DOCKERFILE, "--build-arg ubuntu_version=20.04")
                        }
                    }
                }
            }
        }
        stage("Push to OE Docker Registry") {
            steps {
                script {
                    docker.withRegistry(params.INTERNAL_REPO, env.INTERNAL_REPO_CREDS) {
                        common.exec_with_retry { oe1804.push() }
                        common.exec_with_retry { oe2004.push() }
                        if(params.TAG_LATEST == "true") {
                            common.exec_with_retry { oe1804.push('latest') }
                            common.exec_with_retry { oe2004.push('latest') }
                        }
                    }
                }
            }
        }
        stage("Push to OE Docker Hub Registry") {
            steps {
                script {
                    docker.withRegistry('', DOCKERHUB_REPO_CREDS) {
                        if(PUBLISH_DOCKER_HUB == "true") {
                            common.exec_with_retry { puboe1804.push() }
                            common.exec_with_retry { puboe2004.push() }
                            if(TAG_LATEST == "true") {
                                common.exec_with_retry { puboe1804.push('latest') }
                                common.exec_with_retry { puboe2004.push('latest') }
                            }
                        }
                    }
                }
            }
        }
    }
    post {
        always {
            emailext(
                subject: "Jenkins: ${env.JOB_NAME} [#${env.BUILD_NUMBER}] status is ${currentBuild.currentResult}",
                body: "See build log for details: ${env.BUILD_URL}", 
                recipientProviders: [[$class: 'DevelopersRecipientProvider'], [$class: 'RequesterRecipientProvider']]
            )
        }
    }
}
