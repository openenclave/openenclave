// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

TAG_FULL_IMAGE = params.DOCKER_TAG ?: helpers.get_date(".") + "${BUILD_NUMBER}"

TIMEOUT_MINUTES = 240
DOCKERHUB_REPO_CREDS = "oeciteamdockerhub"

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
        string(name: "INTERNAL_REPO_CRED_ID", defaultValue: "oejenkinscidockerregistry", description: "Credential ID for internal Docker repository")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
        string(name: "AGENTS_LABEL", defaultValue: 'windows-nonsgx', description: "Label of the agent to use to run this job")
        booleanParam(name: "PUBLISH_DOCKER_HUB", defaultValue: false, description: "Publish container to OECITeam Docker Hub?")
        booleanParam(name: "TAG_LATEST", defaultValue: false, description: "Update the latest tag to the currently built DOCKER_TAG")
        booleanParam(name: "PUBLISH_VERSION_FILE", defaultValue: false, description: "Publish versioning information?")
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
                    docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
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
        stage('Publish info') {
            when {
                expression {
                    return params.PUBLISH_VERSION_FILE
                }
            }
            agent {
                label globalvars.AGENTS_LABELS["shared"]
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'github-oeciteam-user-pat',
                                 usernameVariable: 'GIT_USERNAME',
                                 passwordVariable: 'GIT_PASSWORD')]) {
                    sh '''
                        git config --global user.email "${GIT_USERNAME}@microsoft.com"
                        git config --global user.name ${GIT_USERNAME}
                        git checkout --force "oeciteam/publish-docker"
                        git pull
                    '''
                    script {
                    REPOSITORY = params.INTERNAL_REPO - ~"^https://"
                        sh """#!/bin/bash
                            OE_VERSION=\$(grep --max-count=1 --only-matching --perl-regexp 'v\\d+\\.\\d+\\.\\d+(?=_log)' CHANGELOG.md)
                            echo "| Windows Server 2019 | ${REPOSITORY}/oetools-ws2019:${TAG_FULL_IMAGE} | \${OE_VERSION} | None | None |" >> DOCKER_IMAGES.md
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
