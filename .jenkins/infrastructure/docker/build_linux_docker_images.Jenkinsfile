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
        string(name: "CONTAINER_REPO", defaultValue: "openenclave.azurecr.io", description: "Docker repository name")
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
        string(name: "DEVKITS_URI", defaultValue: 'https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/OE-CI-devkits-d1634ce8.tar.gz', description: "Uri for downloading the OECI Devkit")
        string(name: "AGENTS_LABEL", defaultValue: 'acc-ubuntu-20.04', description: "Label of the agent to use to run this job")
        booleanParam(name: "TAG_LATEST", defaultValue: false, description: "Update the latest tag to the currently built DOCKER_TAG")
        booleanParam(name: "BUILD_AZL3_MHSM_PREVIEW", defaultValue: false, description: "Build and publish the Azure Linux 3 MHSM OpenSSL 3.5 preview image?")
    }
    environment {
        // Docker plugin cannot seem to use credentials from Azure Key Vault
        BASE_DOCKERFILE_DIR = ".jenkins/infrastructure/docker/dockerfiles/linux/base/"
        LINUX_DOCKERFILE = ".jenkins/infrastructure/docker/dockerfiles/linux/Dockerfile"
        AZURELINUX3_DOCKERFILE = ".jenkins/infrastructure/docker/dockerfiles/linux/azurelinux3/Dockerfile"
        MHSM_AZURELINUX3_DOCKERFILE = ".jenkins/infrastructure/docker/dockerfiles/linux/azurelinux3/mhsm-preview.Dockerfile"
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
        stage("Install Azure CLI") {
            steps {
                script {
                    common.installAzureCLI()
                }
            }
        }
        stage("Base Image") {
            matrix {
                axes {
                    axis {
                        name 'UBUNTU_RELEASE'
                        values '20.04', '22.04'
                    }
                }
                stages {
                    stage("Build Base") {
                        steps {
                            script {
                                def sgx_version
                                if(UBUNTU_RELEASE == "20.04") {
                                    // Last release for Ubuntu 20.04 is SGX 2.25.100.
                                    sgx_version = "2.25.100"
                                } else {
                                    sgx_version = params.SGX_VERSION
                                }
                                dir(env.BASE_DOCKERFILE_DIR) {
                                    sh """
                                        chmod +x ./build.sh
                                        mkdir "build-${UBUNTU_RELEASE}"
                                        cd "build-${UBUNTU_RELEASE}"
                                        ../build.sh -v "${sgx_version}" -u "${UBUNTU_RELEASE}" -t "${TAG_BASE_IMAGE}"
                                    """
                                }
                            }
                        }
                    }
                    stage("Test Base") {
                        steps {
                            script {
                                def base_image = docker.image("openenclave-base-ubuntu-${UBUNTU_RELEASE}:${TAG_BASE_IMAGE}")
                                base_image.inside(
                                     "--user root:root \
                                     --cap-add=SYS_PTRACE \
                                     --device /dev/sgx_enclave:/dev/sgx_enclave \
                                     --device /dev/sgx_provision:/dev/sgx_provision \
                                     --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                                ) {
                                    sh """
                                        apt update
                                        apt install -y build-essential curl libssl-dev cmake
                                    """
                                    // TODO: For 22.04, automated testing is unavailable until first release is available
                                    if(UBUNTU_RELEASE == "20.04") {
                                        helpers.releaseInstall("latest", "open-enclave", "GitHub")
                                        helpers.TestSamplesCommand(false, "open-enclave")
                                    }
                                }
                                sh """
                                    az login --identity
                                    az acr login --name ${params.CONTAINER_REPO}
                                """
                                docker.withRegistry("https://${params.CONTAINER_REPO}") {
                                    base_image.push()
                                    if ( params.TAG_LATEST ) {
                                        base_image.push('latest')
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
                stage("Ubuntu 20.04") {
                    steps {
                        script {
                            buildArgs = common.dockerBuildArgs(
                                "ubuntu_version=20.04",
                                "devkits_uri=${params.DEVKITS_URI}"
                            )
                            oe2004 = common.dockerImage("oetools-20.04:${TAG_FULL_IMAGE}", LINUX_DOCKERFILE, "${buildArgs}")
                            oe2004.inside(
                                        "--cap-add=SYS_PTRACE \
                                        --device /dev/sgx_provision:/dev/sgx_provision \
                                        --device /dev/sgx_enclave:/dev/sgx_enclave \
                                        --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket") {
                                helpers.releaseInstall("latest", "open-enclave", "GitHub")
                                helpers.TestSamplesCommand(false, "open-enclave")
                            }
                            sh """
                                az login --identity
                                az acr login --name ${params.CONTAINER_REPO}
                            """
                            docker.withRegistry("https://${params.CONTAINER_REPO}") {
                                common.exec_with_retry { oe2004.push() }
                                if ( params.TAG_LATEST ) {
                                    common.exec_with_retry { oe2004.push('latest') }
                                }
                            }
                        }
                    }
                }
                stage("Ubuntu 22.04") {
                    steps {
                        script {
                            buildArgs = common.dockerBuildArgs(
                                "ubuntu_version=22.04",
                                "devkits_uri=${params.DEVKITS_URI}"
                            )
                            oe2204 = common.dockerImage("oetools-22.04:${TAG_FULL_IMAGE}", LINUX_DOCKERFILE, "${buildArgs}")
                            oe2204.inside(
                                 "--cap-add=SYS_PTRACE \
                                 --device /dev/sgx_provision:/dev/sgx_provision \
                                 --device /dev/sgx_enclave:/dev/sgx_enclave \
                                 --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                            ) {
                                sh 'echo "TODO: enable tests after Ubuntu 22.04 release deb is available"'
                                // helpers.releaseInstall("latest", "open-enclave", "GitHub")
                                // helpers.TestSamplesCommand(false, "open-enclave")
                            }
                            sh """
                                az login --identity
                                az acr login --name ${params.CONTAINER_REPO}
                            """
                            docker.withRegistry("https://${params.CONTAINER_REPO}") {
                                common.exec_with_retry { oe2204.push() }
                                if ( params.TAG_LATEST ) {
                                    common.exec_with_retry { oe2204.push('latest') }
                                }
                            }
                        }
                    }
                }
                stage("Azure Linux 3") {
                    steps {
                        script {
                            def oeazl3 = common.dockerImage(
                                "oetools-azl3:${TAG_FULL_IMAGE}",
                                AZURELINUX3_DOCKERFILE
                            )
                            oeazl3.inside("--cap-add=SYS_PTRACE") {
                                sh """
                                    grep --quiet '^ID=azurelinux$' /etc/os-release
                                    clang --version
                                    cmake --version
                                    test -f "\$(clang -print-resource-dir)/include/emmintrin.h"
                                """
                            }
                            sh """
                                az login --identity
                                az acr login --name ${params.CONTAINER_REPO}
                            """
                            docker.withRegistry("https://${params.CONTAINER_REPO}") {
                                common.exec_with_retry { oeazl3.push() }
                                if ( params.TAG_LATEST ) {
                                    common.exec_with_retry { oeazl3.push('latest') }
                                }
                            }

                            if (params.BUILD_AZL3_MHSM_PREVIEW) {
                                sh "rm -rf build/mhsm-preview && mkdir -p build/mhsm-preview/staging"
                                oeazl3.inside("--cap-add=SYS_PTRACE") {
                                    sh """
                                        cmake -S ${WORKSPACE} -B ${WORKSPACE}/build/mhsm-preview/oe -G Ninja \
                                            -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                                            -DCMAKE_INSTALL_PREFIX=/opt/openenclave \
                                            -DBUILD_TESTS=OFF \
                                            -DLVI_MITIGATION=None \
                                            -DLVI_MITIGATION_SKIP_TESTS=ON
                                        cmake --build ${WORKSPACE}/build/mhsm-preview/oe --parallel
                                        DESTDIR=${WORKSPACE}/build/mhsm-preview/staging \
                                            cmake --install ${WORKSPACE}/build/mhsm-preview/oe
                                        tar -C ${WORKSPACE}/build/mhsm-preview/staging/opt \
                                            -czf ${WORKSPACE}/build/mhsm-preview/openenclave-azl3-openssl35-${TAG_FULL_IMAGE}.tar.gz \
                                            openenclave
                                    """
                                }

                                def mhsmBuildArgs = common.dockerBuildArgs(
                                    "OE_IMAGE_VERSION=${TAG_FULL_IMAGE}",
                                    "OE_INSTALL_DIR=build/mhsm-preview/staging/opt/openenclave"
                                )
                                def mhsmImage = common.dockerImage(
                                    "openenclave-mhsm-azl3-openssl35:${TAG_FULL_IMAGE}",
                                    MHSM_AZURELINUX3_DOCKERFILE,
                                    "${mhsmBuildArgs}"
                                )
                                mhsmImage.inside("--entrypoint='' --user root:root") {
                                    sh """
                                        test -x /opt/openenclave/bin/oesign
                                        grep --quiet '# *define OPENSSL_VERSION_TEXT "OpenSSL 3.5.7' \
                                            /opt/openenclave/include/openenclave/3rdparty/openssl_3/openssl/opensslv.h
                                        rpm -q libsgx-enclave-common libsgx-dcap-ql \
                                            libsgx-dcap-quote-verify libsgx-dcap-default-qpl
                                        test -e /usr/lib64/libdcap_quoteprov.so
                                    """
                                }

                                def hasSgxDevices = sh(
                                    script: "test -e /dev/sgx_enclave && test -e /dev/sgx_provision",
                                    returnStatus: true
                                ) == 0
                                if (hasSgxDevices) {
                                    mhsmImage.inside(
                                        "--entrypoint='' \
                                        --device /dev/sgx_provision:/dev/sgx_provision \
                                        --device /dev/sgx_enclave:/dev/sgx_enclave \
                                        --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                                    ) {
                                        sh "oesgx | tee /tmp/oesgx.out && grep --quiet 'supports Software Guard Extensions:SGX1' /tmp/oesgx.out"
                                    }
                                } else {
                                    echo "Skipping MHSM hardware smoke test because SGX devices are unavailable"
                                }

                                docker.withRegistry("https://${params.CONTAINER_REPO}") {
                                    common.exec_with_retry { mhsmImage.push() }
                                    if ( params.TAG_LATEST ) {
                                        common.exec_with_retry { mhsmImage.push('latest') }
                                    }
                                }
                                archiveArtifacts(
                                    artifacts: "build/mhsm-preview/openenclave-azl3-openssl35-${TAG_FULL_IMAGE}.tar.gz",
                                    fingerprint: true
                                )
                            }
                        }
                    }
                }
            }
        }
    }
    post {
        always {
            script {
                helpers.dockerCleanup(params.CONTAINER_REPO)
            }
        }
    }
}
