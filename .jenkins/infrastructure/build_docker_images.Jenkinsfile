// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

GLOBAL_TIMEOUT_MINUTES = 240

OETOOLS_REPO = "https://oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"
OETOOLS_DOCKERHUB_REPO_CREDENTIAL_ID = "oeciteamdockerhub"

def buildDockerImages() {
    node(params.AGENTS_LABEL) {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            stage("Checkout") {
                cleanWs()
                checkout scm
            }
            String buildArgs = oe.dockerBuildArgs("UID=\$(id -u)", "UNAME=\$(id -un)",
                                                  "GID=\$(id -g)", "GNAME=\$(id -gn)")
            stage("Build Ubuntu 16.04 Full Docker Image") {
                oefull1604 = oe.dockerImage("oetools-full-16.04:${DOCKER_TAG}", ".jenkins/infrastructure/dockerfiles/Dockerfile.full", "${buildArgs} --build-arg ubuntu_version=16.04 --build-arg devkits_uri=${DEVKITS_URI}")
                puboefull1604 = oe.dockerImage("oeciteam/oetools-full-16.04:${DOCKER_TAG}", ".jenkins/infrastructure/dockerfiles/Dockerfile.full", "${buildArgs} --build-arg ubuntu_version=16.04 --build-arg devkits_uri=${DEVKITS_URI}")
            }
            stage("Build Ubuntu 18.04 Full Docker Image") {
                oefull1804 = oe.dockerImage("oetools-full-18.04:${DOCKER_TAG}", ".jenkins/infrastructure/dockerfiles/Dockerfile.full", "${buildArgs} --build-arg ubuntu_version=18.04 --build-arg devkits_uri=${DEVKITS_URI}")
                puboefull1804 = oe.dockerImage("oeciteam/oetools-full-18.04:${DOCKER_TAG}", ".jenkins/infrastructure/dockerfiles/Dockerfile.full", "${buildArgs} --build-arg ubuntu_version=18.04 --build-arg devkits_uri=${DEVKITS_URI}")
            }
            stage("Build Ubuntu 18.04 Minimal Docker image") {
                oeminimal1804 = oe.dockerImage("oetools-minimal-18.04:${DOCKER_TAG}", ".jenkins/infrastructure/dockerfiles/Dockerfile.minimal", "${buildArgs} --build-arg ubuntu_version=18.04")
                puboeminimal1804 = oe.dockerImage("oeciteam/oetools-minimal-18.04:${DOCKER_TAG}", ".jenkins/infrastructure/dockerfiles/Dockerfile.minimal", "${buildArgs} --build-arg ubuntu_version=18.04")
            }
            stage("Build Ubuntu Deploy Docker image") {
                oeDeploy = oe.dockerImage("oetools-deploy:${DOCKER_TAG}", ".jenkins/infrastructure/dockerfiles/Dockerfile.deploy", buildArgs)
                puboeDeploy = oe.dockerImage("oeciteam/oetools-deploy:${DOCKER_TAG}", ".jenkins/infrastructure/dockerfiles/Dockerfile.deploy", buildArgs)
            }
            stage("Push to OE Docker Registry") {
                docker.withRegistry(OETOOLS_REPO, OETOOLS_REPO_CREDENTIAL_ID) {
                    oe.exec_with_retry { oefull1604.push() }
                    oe.exec_with_retry { oefull1804.push() }
                    oe.exec_with_retry { oeminimal1804.push() }
                    oe.exec_with_retry { oeDeploy.push() }
                    if(TAG_LATEST == "true") {
                        oe.exec_with_retry { oefull1604.push('latest') }
                        oe.exec_with_retry { oefull1804.push('latest') }
                        oe.exec_with_retry { oeminimal1804.push('latest') }
                        oe.exec_with_retry { oeDeploy.push('latest') }
                    }
                }
            }
            stage("Push to OE Docker Hub Registry") {
                docker.withRegistry('', OETOOLS_DOCKERHUB_REPO_CREDENTIAL_ID) {
                    if(TAG_LATEST == "true") {
                        oe.exec_with_retry { puboefull1604.push() }
                        oe.exec_with_retry { puboefull1804.push() }
                        oe.exec_with_retry { puboeminimal1804.push() }
                        oe.exec_with_retry { puboeDeploy.push() }
                        oe.exec_with_retry { puboefull1604.push('latest') }
                        oe.exec_with_retry { puboefull1804.push('latest') }
                        oe.exec_with_retry { puboeminimal1804.push('latest') }
                        oe.exec_with_retry { puboeDeploy.push('latest') }
                    }
                }
            }
        }
    }
}

buildDockerImages()
