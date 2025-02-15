// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

GLOBAL_TIMEOUT_MINUTES = 90
library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"
INTERNAL_REPO_NAME = params.INTERNAL_REPO - ~"^(https|http)://"
PUBLIC_REPO_NAME = params.PUBLIC_REPO - ~"^(https|http)://"

pipeline {
    agent {
        label globalvars.AGENTS_LABELS['ubuntu-nonsgx']
    }
    parameters {
        string(name: "REPOSITORY_NAME", defaultValue: "openenclave/openenclave", description: "GitHub repository to checkout")
        string(name: "BRANCH_NAME", defaultValue: "master", description: "The branch used to checkout the repository")
        string(name: "INTERNAL_LINUX_TAG", description: "[REQUIRED] Specify the Linux Docker image tag to pull from the internal repository")
        string(name: "PUBLIC_LINUX_TAG", description: "[REQUIRED] Specify the Linux Docker image tag to push to the public repository")
        string(name: "INTERNAL_WINDOWS_TAG", description: "[REQUIRED] Specify the Windows Docker image tag to pull from the internal repository")
        string(name: "PUBLIC_WINDOWS_TAG", description: "[REQUIRED] Specify the Windows Docker image tag to push to the public repository")
        string(name: "INTERNAL_REPO", defaultValue: "https://oejenkinscidockerregistry.azurecr.io", description: "Url for internal Docker repository")
        string(name: "INTERNAL_REPO_CRED_ID", defaultValue: "oejenkinscidockerregistry", description: "Credential ID for internal Docker repository")
        string(name: "PUBLIC_REPO", defaultValue: "https://openenclavedockerregistry.azurecr.io", description: "Url for internal Docker repository")
        string(name: "PUBLIC_REPO_CRED_ID", defaultValue: "openenclavedockerregistry-userkey-jenkins", description: "Credential ID for internal Docker repository")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
        booleanParam(name: "PUBLISH_LINUX", defaultValue: true, description: "Publish Linux Docker images?")
        booleanParam(name: "PUBLISH_WINDOWS", defaultValue: true, description: "Publish Windows Docker images?")
        booleanParam(name: "TAG_LATEST", defaultValue: true, description: "Update the latest tag to the currently built DOCKER_TAG")
        booleanParam(name: "PUBLISH_VERSION_FILE", defaultValue: true, description: "Publish versioning information?")
    }
    environment {
        OECITEAM_BRANCH = "oeciteam/publish-docker"
    }
    stages {
        stage('Push to public repo') {
            parallel {
                stage('Linux containers') {
                    when {
                        expression { return params.PUBLISH_LINUX }
                    }
                    stages {
                        stage('Pull images') {
                            steps {
                                script {
                                    docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                        sh """
                                            docker pull ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.INTERNAL_LINUX_TAG}
                                            docker pull ${INTERNAL_REPO_NAME}/oetools-20.04:${params.INTERNAL_LINUX_TAG}
                                            docker pull ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.INTERNAL_LINUX_TAG}
                                            docker pull ${INTERNAL_REPO_NAME}/oetools-22.04:${params.INTERNAL_LINUX_TAG}
                                        """
                                    }
                                }
                            }
                        }
                        stage('Push tag to public repo') {
                            steps {
                                script {
                                    docker.withRegistry(params.PUBLIC_REPO, params.PUBLIC_REPO_CRED_ID) {
                                        sh """
                                            docker tag ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.INTERNAL_LINUX_TAG} ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.PUBLIC_LINUX_TAG}
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-20.04:${params.INTERNAL_LINUX_TAG} ${PUBLIC_REPO_NAME}/oetools-20.04:${params.PUBLIC_LINUX_TAG}
                                            docker push ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.PUBLIC_LINUX_TAG}
                                            docker push ${PUBLIC_REPO_NAME}/oetools-20.04:${params.PUBLIC_LINUX_TAG}

                                            docker tag ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.INTERNAL_LINUX_TAG} ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.PUBLIC_LINUX_TAG}
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-22.04:${params.INTERNAL_LINUX_TAG} ${PUBLIC_REPO_NAME}/oetools-22.04:${params.PUBLIC_LINUX_TAG}
                                            docker push ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.PUBLIC_LINUX_TAG}
                                            docker push ${PUBLIC_REPO_NAME}/oetools-22.04:${params.PUBLIC_LINUX_TAG}

                                        """
                                    }
                                }
                            }
                        }
                        stage('Push latest to public repo') {
                            when {
                                expression { return params.TAG_LATEST }
                            }
                            steps {
                                script {
                                    docker.withRegistry(params.PUBLIC_REPO, params.PUBLIC_REPO_CRED_ID) {
                                        sh """
                                            docker tag ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.PUBLIC_LINUX_TAG} ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-20.04:latest
                                            docker tag ${PUBLIC_REPO_NAME}/oetools-20.04:${params.PUBLIC_LINUX_TAG} ${PUBLIC_REPO_NAME}/oetools-20.04:latest
                                            docker push ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-20.04:latest
                                            docker push ${PUBLIC_REPO_NAME}/oetools-20.04:latest

                                            docker tag ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.PUBLIC_LINUX_TAG} ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-22.04:latest
                                            docker tag ${PUBLIC_REPO_NAME}/oetools-22.04:${params.PUBLIC_LINUX_TAG} ${PUBLIC_REPO_NAME}/oetools-22.04:latest
                                            docker push ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-22.04:latest
                                            docker push ${PUBLIC_REPO_NAME}/oetools-22.04:latest
                                        """
                                    }
                                }
                            }
                        }
                        stage('Push tag to internal repo') {
                            when {
                                expression { return params.INTERNAL_LINUX_TAG != params.PUBLIC_LINUX_TAG }
                            }
                            steps {
                                script {
                                    docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                        sh """
                                            docker tag ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.INTERNAL_LINUX_TAG} ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.PUBLIC_LINUX_TAG}
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-20.04:${params.INTERNAL_LINUX_TAG} ${INTERNAL_REPO_NAME}/oetools-20.04:${params.PUBLIC_LINUX_TAG}
                                            docker push ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.PUBLIC_LINUX_TAG}
                                            docker push ${INTERNAL_REPO_NAME}/oetools-20.04:${params.PUBLIC_LINUX_TAG}

                                            docker tag ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.INTERNAL_LINUX_TAG} ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.PUBLIC_LINUX_TAG}
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-22.04:${params.INTERNAL_LINUX_TAG} ${INTERNAL_REPO_NAME}/oetools-22.04:${params.PUBLIC_LINUX_TAG}
                                            docker push ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.PUBLIC_LINUX_TAG}
                                            docker push ${INTERNAL_REPO_NAME}/oetools-22.04:${params.PUBLIC_LINUX_TAG}
                                        """
                                    }
                                }
                            }
                        }
                        stage('Push latest to internal repo') {
                            when {
                                expression { return params.TAG_LATEST }
                            }
                            steps {
                                script {
                                    docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                        sh """
                                            docker tag ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.PUBLIC_LINUX_TAG} ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-20.04:latest
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-20.04:${params.PUBLIC_LINUX_TAG} ${INTERNAL_REPO_NAME}/oetools-20.04:latest
                                            docker push ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-20.04:latest
                                            docker push ${INTERNAL_REPO_NAME}/oetools-20.04:latest

                                            docker tag ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.PUBLIC_LINUX_TAG} ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-22.04:latest
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-22.04:${params.PUBLIC_LINUX_TAG} ${INTERNAL_REPO_NAME}/oetools-22.04:latest
                                            docker push ${INTERNAL_REPO_NAME}/openenclave-base-ubuntu-22.04:latest
                                            docker push ${INTERNAL_REPO_NAME}/oetools-22.04:latest
                                        """
                                    }
                                }
                            }
                        }
                    }
                }
                stage('Windows containers') {
                    when {
                        beforeAgent true
                        expression { return params.PUBLISH_WINDOWS }
                    }
                    agent {
                        label globalvars.AGENTS_LABELS['ws2022-nonsgx']
                    }
                    stages {
                        stage('Pull images') {
                            steps {
                                script {
                                    docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                        powershell """
                                            docker pull ${INTERNAL_REPO_NAME}/oetools-ws2022:${params.INTERNAL_WINDOWS_TAG}
                                        """
                                    }
                                }
                            }
                        }
                        stage('Push tag to public repo') {
                            steps {
                                script {
                                    docker.withRegistry(params.PUBLIC_REPO, params.PUBLIC_REPO_CRED_ID) {
                                        powershell """
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-ws2022:${params.INTERNAL_WINDOWS_TAG} ${PUBLIC_REPO_NAME}/oetools-ws2022:${params.PUBLIC_WINDOWS_TAG}
                                            docker push ${PUBLIC_REPO_NAME}/oetools-ws2022:${params.PUBLIC_WINDOWS_TAG}
                                        """
                                    }
                                }
                            }
                        }
                        stage('Push latest to public repo') {
                            when {
                                expression { return params.TAG_LATEST }
                            }
                            steps {
                                script {
                                    docker.withRegistry(params.PUBLIC_REPO, params.PUBLIC_REPO_CRED_ID) {
                                        powershell """
                                            docker tag ${PUBLIC_REPO_NAME}/oetools-ws2022:${params.PUBLIC_WINDOWS_TAG} ${PUBLIC_REPO_NAME}/oetools-ws2022:latest
                                            docker push ${PUBLIC_REPO_NAME}/oetools-ws2022:latest
                                        """
                                    }
                                }
                            }
                        }
                        stage('Push tag to internal repo') {
                            when {
                                expression { return params.INTERNAL_WINDOWS_TAG != params.PUBLIC_WINDOWS_TAG }
                            }
                            steps {
                                script {
                                    docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                        powershell """
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-ws2022:${params.INTERNAL_WINDOWS_TAG} ${INTERNAL_REPO_NAME}/oetools-ws2022:${params.PUBLIC_WINDOWS_TAG}
                                            docker push ${INTERNAL_REPO_NAME}/oetools-ws2022:${params.PUBLIC_WINDOWS_TAG}
                                        """
                                    }
                                }
                            }
                        }
                        stage('Push latest to internal repo') {
                            when {
                                expression { return params.TAG_LATEST }
                            }
                            steps {
                                script {
                                    docker.withRegistry(params.INTERNAL_REPO, params.INTERNAL_REPO_CRED_ID) {
                                        powershell """
                                            docker tag ${INTERNAL_REPO_NAME}/oetools-ws2022:${params.INTERNAL_WINDOWS_TAG} ${INTERNAL_REPO_NAME}/oetools-ws2022:latest
                                            docker push ${INTERNAL_REPO_NAME}/oetools-ws2022:latest
                                        """
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        stage('Publish version file') {
            when {
                anyOf {
                    expression { return params.PUBLISH_LINUX }
                    expression { return params.PUBLISH_WINDOWS }
                }
                expression { return params.PUBLISH_VERSION_FILE }
            }
            stages {   
                stage('Init') {
                    steps {
                        checkout([$class: 'GitSCM',
                            branches: [[name: 'master']],
                            extensions: [
                                [
                                    $class: 'PruneStaleBranch',
                                    $class: 'SubmoduleOption',
                                    disableSubmodules: true,
                                    recursiveSubmodules: false,
                                    trackingSubmodules: false
                                ]
                            ], 
                            userRemoteConfigs: [[url: "https://github.com/openenclave/openenclave"]]])
                        sh """
                            if git fetch origin ${OECITEAM_BRANCH}; then
                                git checkout ${OECITEAM_BRANCH} --force
                            else
                                git fetch origin master
                                git checkout -b ${OECITEAM_BRANCH} --track remotes/origin/master --force
                            fi
                        """
                        script {
                            OE_VERSION = helpers.getLatestOpenEnclaveRelease()
                        }
                    }
                }
                stage('Add details') {
                    steps {
                        script {
                            // Compose the new DOCKER_IMAGES.md file in 3 sections:
                            // 1. "Current versions" header (first 3 lines)
                            // 2. New images
                            // 3. "Previous versions" header
                            // 4. Current images -> Previous images
                            // 5. Previous images

                            // Add "Current versions" header
                            sh """
                                head -n 3 DOCKER_IMAGES.md > DOCKER_IMAGES_new.md
                            """
                            // Add new images
                            if (params.PUBLISH_WINDOWS) {
                                sh """
                                    echo "| Windows Server 2022 | ${PUBLIC_REPO_NAME}/oetools-ws2022:${PUBLIC_WINDOWS_TAG} | ${OE_VERSION} | None | None |" >> DOCKER_IMAGES_new.md
                                """
                            }
                            if (params.PUBLISH_LINUX) {
                                // The PSW and DCAP versions between full, base, and Ubuntu versions should always be the same
                                // But we do this as a quick and easy check to ensure all versions are consistent
                                // Ubuntu 22.04
                                BASE_2204_PSW  = helpers.dockerGetAptPackageVersion("${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.PUBLIC_LINUX_TAG}", "libsgx-enclave-common")
                                BASE_2204_DCAP = helpers.dockerGetAptPackageVersion("${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-22.04:${params.PUBLIC_LINUX_TAG}", "libsgx-ae-id-enclave")
                                FULL_2204_PSW  = helpers.dockerGetAptPackageVersion("${PUBLIC_REPO_NAME}/oetools-22.04:${params.PUBLIC_LINUX_TAG}", "libsgx-enclave-common")
                                FULL_2204_DCAP = helpers.dockerGetAptPackageVersion("${PUBLIC_REPO_NAME}/oetools-22.04:${params.PUBLIC_LINUX_TAG}", "libsgx-ae-id-enclave")
                                // Ubuntu 20.04
                                BASE_2004_PSW  = helpers.dockerGetAptPackageVersion("${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.PUBLIC_LINUX_TAG}", "libsgx-enclave-common")
                                BASE_2004_DCAP = helpers.dockerGetAptPackageVersion("${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-20.04:${params.PUBLIC_LINUX_TAG}", "libsgx-ae-id-enclave")
                                FULL_2004_PSW  = helpers.dockerGetAptPackageVersion("${PUBLIC_REPO_NAME}/oetools-20.04:${params.PUBLIC_LINUX_TAG}", "libsgx-enclave-common")
                                FULL_2004_DCAP = helpers.dockerGetAptPackageVersion("${PUBLIC_REPO_NAME}/oetools-20.04:${params.PUBLIC_LINUX_TAG}", "libsgx-ae-id-enclave")

                                sh """
                                    echo "| Base Ubuntu 22.04 | ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-22.04:${PUBLIC_LINUX_TAG} | ${OE_VERSION} | ${BASE_2204_PSW} | ${BASE_2204_DCAP} |" >> DOCKER_IMAGES_new.md
                                    echo "| Full Ubuntu 22.04 | ${PUBLIC_REPO_NAME}/oetools-22.04:${PUBLIC_LINUX_TAG} | ${OE_VERSION} | ${FULL_2204_PSW} | ${FULL_2204_DCAP} |" >> DOCKER_IMAGES_new.md
                                    echo "| Base Ubuntu 20.04 | ${PUBLIC_REPO_NAME}/openenclave-base-ubuntu-20.04:${PUBLIC_LINUX_TAG} | ${OE_VERSION} | ${BASE_2004_PSW} | ${BASE_2004_DCAP} |" >> DOCKER_IMAGES_new.md
                                    echo "| Full Ubuntu 20.04 | ${PUBLIC_REPO_NAME}/oetools-20.04:${PUBLIC_LINUX_TAG} | ${OE_VERSION} | ${FULL_2004_PSW} | ${FULL_2004_DCAP} |" >> DOCKER_IMAGES_new.md
                                """
                            }
                        }
                        // Add "Previous versions" header, current images, and previous images
                        sh """
                            # Find the line number of the "Previous versions" header
                            line_prev_ver=\$(awk '/^# Previous versions\$/ {print FNR}' DOCKER_IMAGES.md)
                            tail +\$((line_prev_ver - 1)) DOCKER_IMAGES.md | head -n 4 >> DOCKER_IMAGES_new.md
                            head -n \$((line_prev_ver - 2 )) DOCKER_IMAGES.md | tail +4 >> DOCKER_IMAGES_new.md
                            tail -n +\$((line_prev_ver + 3)) DOCKER_IMAGES.md >> DOCKER_IMAGES_new.md
                            mv DOCKER_IMAGES_new.md DOCKER_IMAGES.md
                        """
                    }
                }
                stage('Commit and push') {
                    steps {
                        withCredentials([usernamePassword(credentialsId: 'github-oeciteam-user-pat',
                                                        usernameVariable: 'GIT_USERNAME',
                                                        passwordVariable: 'GIT_PASSWORD')]) {
                            sh '''
                                git add DOCKER_IMAGES.md
                                git config --global user.email "${GIT_USERNAME}@microsoft.com"
                                git config --global user.name ${GIT_USERNAME}
                                git commit -sm "Publish Docker Images"
                                git push --force https://${GIT_PASSWORD}@github.com/openenclave/openenclave.git HEAD:${OECITEAM_BRANCH}
                            '''
                        }
                    }
                }
            }
        }
    }
}
