// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

pipeline {
    agent {
        label globalvars.AGENTS_LABELS["ubuntu-nonsgx"]
    }
    options {
        timeout(time: 240, unit: 'MINUTES')
    }
    parameters {
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
        stage("Build") {
            parallel {
                stage("Build Ubuntu 18.04 Docker Image") {
                    steps {
                        script {
                            docker.withRegistry(params.INTERNAL_REPO, env.INTERNAL_REPO_CREDS) {
                                buildArgs = common.dockerBuildArgs("UID=\$(id -u)", "UNAME=\$(id -un)",
                                                                   "GID=\$(id -g)", "GNAME=\$(id -gn)")
                                oe1804 = common.dockerImage("oetools-18.04:${params.DOCKER_TAG}", env.LINUX_DOCKERFILE, "${buildArgs} --build-arg ubuntu_version=18.04")
                                puboe1804 = common.dockerImage("oeciteam/oetools-18.04:${params.DOCKER_TAG}", env.LINUX_DOCKERFILE, "${buildArgs} --build-arg ubuntu_version=18.04")
                            }
                        }
                    }
                }
                stage("Build Ubuntu 20.04 Docker Image") {
                    steps {
                        script {
                            buildArgs = common.dockerBuildArgs("UID=\$(id -u)", "UNAME=\$(id -un)",
                                                               "GID=\$(id -g)", "GNAME=\$(id -gn)")
                            oe2004 = common.dockerImage("oetools-20.04:${params.DOCKER_TAG}", env.LINUX_DOCKERFILE, "${buildArgs} --build-arg ubuntu_version=20.04")
                            puboe2004 = common.dockerImage("oeciteam/oetools-20.04:${params.DOCKER_TAG}", env.LINUX_DOCKERFILE, "${buildArgs} --build-arg ubuntu_version=20.04")
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
                    docker.withRegistry('', env.DOCKERHUB_REPO_CREDS) {
                        if(params.PUBLISH_DOCKER_HUB == "true") {
                            common.exec_with_retry { puboe1804.push() }
                            common.exec_with_retry { puboe2004.push() }
                            if(params.TAG_LATEST == "true") {
                                common.exec_with_retry { puboe1804.push('latest') }
                                common.exec_with_retry { puboe2004.push('latest') }
                            }
                        }
                    }
                }
            }
        }
    }
}
