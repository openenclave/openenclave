// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

TAG_FULL_IMAGE = params.DOCKER_TAG ?: helpers.get_date(".")

AGENTS_LABEL = params.AGENTS_LABEL
TIMEOUT_MINUTES = params.TIMEOUT_MINUTES ?: 240

INTERNAL_REPO = params.INTERNAL_REPO ?: "https://oejenkinscidockerregistry.azurecr.io"
INTERNAL_REPO_CREDS = params.INTERNAL_REPO_CREDS ?: "oejenkinscidockerregistry"
DOCKERHUB_REPO_CREDS = params.DOCKERHUB_REPO_CREDS ?: "oeciteamdockerhub"

pipeline {
    agent {
        label globalvars.AGENTS_LABELS[params.AGENTS_LABEL]
    }
    options {
        timeout(time: 240, unit: 'MINUTES')
    }
    parameters {
        string(name: "REPOSITORY_NAME", defaultValue: "openenclave/openenclave", description: "GitHub repository to checkout")
        string(name: "BRANCH_NAME", defaultValue: "master", description: "The branch used to checkout the repository")
        string(name: "DOCKER_TAG", defaultValue: "", description: "[OPTIONAL] Specify the tag for the new Docker images.")
        string(name: "INTERNAL_REPO", defaultValue: "https://oejenkinscidockerregistry.azurecr.io", description: "Url for internal Docker repository")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
        string(name: "AGENTS_LABEL", defaultValue: 'acc-ubuntu-18.04', description: "Label of the agent to use to run this job")
        booleanParam(name: "PUBLISH_DOCKER_HUB", defaultValue: false, description: "Publish container to OECITeam Docker Hub?")
        booleanParam(name: "TAG_LATEST", defaultValue: false, description: "Update the latest tag to the currently built DOCKER_TAG")
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
        stage("Build Windows Server 2019 Docker Image") {
            steps {
                script {
                    oe2019 = common.dockerImage("oetools-ws2019:${TAG_FULL_IMAGE}", ".jenkins/infrastructure/docker/dockerfiles/windows/Dockerfile")
                }
            }
        }
        stage("Push to OE Docker Registry") {
            steps {
                script {
                    docker.withRegistry(INTERNAL_REPO, INTERNAL_REPO_CREDS) {
                        common.exec_with_retry { oe2019.push() }
                        if ( TAG_LATEST ) {
                            common.exec_with_retry { oe2019.push('latest') }
                        }
                    }
                }
            }
        }
        stage("Push to OE Docker Hub Registry") {
            when {
                expression { 
                    return params.PUBLISH_DOCKER_HUB
                }
            }
            steps {
                script {
                    docker.withRegistry('', DOCKERHUB_REPO_CREDS) {
                        if ( PUBLISH_DOCKER_HUB ) {
                            common.exec_with_retry { oe2019.push() }
                            if( TAG_LATEST ) {
                                common.exec_with_retry { oe2019.push('latest') }
                            }
                        }
                    }
                }
            }
        }
    }
}
