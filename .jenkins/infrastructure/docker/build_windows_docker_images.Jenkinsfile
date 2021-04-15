// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

AGENTS_LABEL = params.AGENTS_LABEL
TIMEOUT_MINUTES = params.TIMEOUT_MINUTES ?: 240

INTERNAL_REPO = params.INTERNAL_REPO ?: "https://oejenkinscidockerregistry.azurecr.io"
INTERNAL_REPO_CREDS = params.INTERNAL_REPO_CREDS ?: "oejenkinscidockerregistry"
DOCKERHUB_REPO_CREDS = params.DOCKERHUB_REPO_CREDS ?: "oeciteamdockerhub"

def buildWindowsDockerContainers() {
    node(AGENTS_LABEL) {
        timeout(TIMEOUT_MINUTES) {
            stage("Checkout") {
                cleanWs()
                checkout scm
            }
            stage("Build Windows Server 2019 Docker Image") {
                oe2019 = oe.dockerImage("oetools-ws2019:${DOCKER_TAG}", ".jenkins/infrastructure/docker/dockerfiles/windows/Dockerfile")
                puboe2019 = oe.dockerImage("oeciteam/oetools-ws2019:${DOCKER_TAG}", ".jenkins/infrastructure/docker/dockerfiles/windows/Dockerfile")
            }
            stage("Push to OE Docker Registry") {
                docker.withRegistry(INTERNAL_REPO, INTERNAL_REPO_CREDS) {
                    oe.exec_with_retry { oe2019.push() }
                    if(TAG_LATEST == "true") {
                        oe.exec_with_retry { oe2019.push('latest') }
                    }
                }
            }
            stage("Push to OE Docker Hub Registry") {
                docker.withRegistry('', DOCKERHUB_REPO_CREDS) {
                    if(TAG_LATEST == "true") {
                        oe.exec_with_retry { puboe2019.push() }
                        oe.exec_with_retry { puboe2019.push('latest') }
                    }
                }
            }
        }
    }
}

buildWindowsDockerContainers()
