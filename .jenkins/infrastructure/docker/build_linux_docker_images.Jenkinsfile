// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

AGENTS_LABEL = params.AGENTS_LABEL
TIMEOUT_MINUTES = params.TIMEOUT_MINUTES ?: 240

INTERNAL_REPO = params.INTERNAL_REPO ?: "https://oejenkinscidockerregistry.azurecr.io"
INTERNAL_REPO_CREDS = params.INTERNAL_REPO_CREDS ?: "oejenkinscidockerregistry"
DOCKERHUB_REPO_CREDS = params.DOCKERHUB_REPO_CREDS ?: "oeciteamdockerhub"
LINUX_DOCKERFILE = ".jenkins/infrastructure/docker/dockerfiles/linux/Dockerfile"

def buildLinuxDockerContainers() {
    node(AGENTS_LABEL) {
        timeout(TIMEOUT_MINUTES) {
            stage("Checkout") {
                cleanWs()
                checkout scm
            }
            String buildArgs = oe.dockerBuildArgs("UID=\$(id -u)", "UNAME=\$(id -un)",
                                                  "GID=\$(id -g)", "GNAME=\$(id -gn)")
            parallel "Build Ubuntu 18.04 Docker Image": {
                stage("Build Ubuntu 18.04 Docker Image") {
                    oe1804 = oe.dockerImage("oetools-18.04:${DOCKER_TAG}", LINUX_DOCKERFILE, "${buildArgs} --build-arg ubuntu_version=18.04 --build-arg devkits_uri=${DEVKITS_URI}")
                    puboe1804 = oe.dockerImage("oeciteam/oetools-18.04:${DOCKER_TAG}", LINUX_DOCKERFILE, "${buildArgs} --build-arg ubuntu_version=18.04 --build-arg devkits_uri=${DEVKITS_URI}")
                }
            }, "Build Ubuntu 20.04 Docker Image": {
                stage("Build Ubuntu 20.04 Docker Image") {
                    oe2004 = oe.dockerImage("oetools-20.04:${DOCKER_TAG}",LINUX_DOCKERFILE, "${buildArgs} --build-arg ubuntu_version=20.04 --build-arg devkits_uri=${DEVKITS_URI}")
                    puboe2004 = oe.dockerImage("oeciteam/oetools-20.04:${DOCKER_TAG}", LINUX_DOCKERFILE, "${buildArgs} --build-arg ubuntu_version=20.04 --build-arg devkits_uri=${DEVKITS_URI}")
                }
            }
            stage("Push to OE Docker Registry") {
                docker.withRegistry(INTERNAL_REPO, INTERNAL_REPO_CREDS) {
                    oe.exec_with_retry { oe1804.push() }
                    oe.exec_with_retry { oe2004.push() }
                    if(TAG_LATEST == "true") {
                        oe.exec_with_retry { oe1804.push('latest') }
                        oe.exec_with_retry { oe2004.push('latest') }
                    }
                }
            }
            stage("Push to OE Docker Hub Registry") {
                docker.withRegistry('', DOCKERHUB_REPO_CREDS) {
                    if(TAG_LATEST == "true") {
                        oe.exec_with_retry { puboe1804.push() }
                        oe.exec_with_retry { puboe2004.push() }
                        oe.exec_with_retry { puboe1804.push('latest') }
                        oe.exec_with_retry { puboe2004.push('latest') }
                    }
                }
            }
        }
    }
}

buildLinuxDockerContainers()
