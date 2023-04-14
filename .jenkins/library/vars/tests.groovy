// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*************************************
* Shared Library for OpenEnclave Tests
*************************************/

// Azure Linux

/* Builds and runs code coverage tests for OE on Ubuntu
 *
 *  @param version: The Ubuntu version to use
 *  @param compiler: The compiler to use
 *  @param build_type: The cmake build type to use. Choice of: Debug, Release, or RelWithDebInfo
 */
def ACCCodeCoverageTest(String version, String compiler, String build_type) {
    stage("ACC ${version} ${compiler} ${build_type} Code Coverage") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = helpers.CmakeArgs(build_type, "ON", "OFF")
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ${helpers.TestCommand()}
                           ninja code_coverage

                           genhtml --branch-coverage -o html_lcov coverage/cov_filtered.info
                           """
                common.Run(compiler, task)

                publishHTML(target: [
                    allowMissing: false,
                    alwaysLinkToLastBuild: false,
                    keepAll: true,
                    reportDir: "${WORKSPACE}/build/html_lcov",
                    reportFiles: 'index.html',
                    reportName: 'Code Coverage Report',
                    reportTitles: ''])
            }
        }
    }
}

/* Builds and runs ctest for OE on Ubuntu
 *
 *  @param label: the label of the Jenkins agent to use
 *  @param compiler: The compiler to use
 *  @param build_type: The cmake build type to use. Choice of: Debug, Release, or RelWithDebInfo
 *  @param extra_cmake_args: Extra cmake args to pass to the build
 *  @param fresh_install: whether to start with a plain VM and install OE dependencies
 */
def ACCTest(String label, String compiler, String build_type, List extra_cmake_args = [], boolean fresh_install = false) {
    stage("${label} ${compiler} ${build_type} ${extra_cmake_args} ${fresh_install ? ", e2e" : ""}") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                if (fresh_install) {
                    sh  """
                        sudo bash scripts/ansible/install-ansible.sh
                        """
                    retry(5) {
                        ret = sh(
                            script: 'sudo ansible-playbook scripts/ansible/oe-contributors-acc-setup.yml',
                            returnStatus: true
                        )
                        if (ret != 0) {
                            sleep time: 60, unit: 'SECONDS'
                            error "Failed OE Ansible setup. Retrying..."
                        }
                    }
                }
                sh """
                    sudo apt list --installed | grep sgx
                """
                def cmakeArgs = helpers.CmakeArgs(build_type,"OFF","ON","-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin",extra_cmake_args.join(' '))
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ${helpers.TestCommand()}
                           """
                common.Run(compiler, task)
            }
        }
    }
}

/* Tests upgrading OE on Ubuntu from the latest release to the current build
 *  This is done by installing the latest release, building the current build,
 *  and then installing the current build.
 *
 *  @param version: The Ubuntu version to use
 *  @param compiler: The compiler to use
 *  @param extra_cmake_args: Extra cmake args to pass to the build 
 * 
 */
def ACCUpgradeTest(String version, String compiler, List extra_cmake_args = []) {
    stage("ACC Upgrade ${version} RelWithDebInfo, extra_cmake_args: ${extra_cmake_args}") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = helpers.CmakeArgs("RelWithDebInfo","OFF","ON","-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin",extra_cmake_args.join(' '))
                common.Run(compiler, helpers.InstallReleaseCommand(version))
                helpers.TestSamplesCommand()
                common.Run(compiler, helpers.ninjaBuildCommand(cmakeArgs))
                common.Run(compiler, helpers.InstallBuildCommand())
                helpers.TestSamplesCommand()
            }
        }
    }
}

/* Tests building and running OE in a container environment
 *
 *  @param version: The version of the container to use
 *  @param compiler: The compiler to use
 *  @param extra_cmake_args: Extra cmake args to pass to the build
 */
def ACCContainerTest(String version, String compiler, List extra_cmake_args = []) {
    stage("ACC Container ${version} RelWithDebInfo, extra_cmake_args: ${extra_cmake_args}") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = helpers.CmakeArgs("RelWithDebInfo","OFF","ON","-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin",extra_cmake_args.join(' '))
                def devices = helpers.getDockerSGXDevices("ubuntu", helpers.getUbuntuReleaseVer())
                def runArgs = "--user root:root --cap-add=SYS_PTRACE ${devices} --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                println("${globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]} running Docker container with ${devices}")
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ${helpers.TestCommand()}
                           """
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }
}

/* Tests building and packing OE in a container environment
 *
 *  @param version: The version of the container to use
 *  @param extra_cmake_args: Extra cmake args to pass to the build
 */
def ACCPackageTest(String version, List extra_cmake_args = []) {
    stage("ACC Package ${version} RelWithDebInfo ${extra_cmake_args}") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = helpers.CmakeArgs("RelWithDebInfo","OFF","ON","-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin",extra_cmake_args.join(' '))
                def devices = helpers.getDockerSGXDevices("ubuntu", helpers.getUbuntuReleaseVer())
                println("Running Docker container with ${devices}")
                common.ContainerTasks(
                    "oetools-${version}:${params.DOCKER_TAG}",
                    globalvars.COMPILER,
                    [
                    common.Run(
                        globalvars.COMPILER,
                        """
                        ${helpers.ninjaBuildCommand(cmakeArgs)}
                        ${helpers.InstallBuildCommand()}
                        """
                    ),
                    helpers.TestSamplesCommand()
                    ],
                    "--cap-add=SYS_PTRACE ${devices} --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                )
            }
        }
    }
}

/* Tests OE host verification.
 * This will generate the necessary certs on Ubuntu and then
 * verify on another Ubuntu and Windows node.
 *
 *  @param version: The version of the container to use
 *  @param build_type: The build type to use
 *  @param compiler: The compiler to use
 */
def ACCHostVerificationTest(String version, String build_type, String compiler) {
    stage("ACC ${version} Generate Quote") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = "-G Ninja -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
                def devices = helpers.getDockerSGXDevices("ubuntu", helpers.getUbuntuReleaseVer())
                def runArgs = "--user root:root --cap-add=SYS_PTRACE ${devices} --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                println("ACC-${version} running Docker container with ${devices}")
                println("Generating certificates and reports ...")
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           pushd tests/host_verify/host
                           openssl ecparam -name prime256v1 -genkey -noout -out keyec.pem
                           openssl ec -in keyec.pem -pubout -out publicec.pem
                           openssl genrsa -out keyrsa.pem 2048
                           openssl rsa -in keyrsa.pem -outform PEM -pubout -out publicrsa.pem
                           ../../../output/bin/oeutil gen --format cert keyec.pem publicec.pem --out sgx_cert_ec.der --verify
                           ../../../output/bin/oeutil gen --format cert keyrsa.pem publicrsa.pem --out sgx_cert_rsa.der --verify
                           ../../../output/bin/oeutil gen --format legacy_report_remote --out sgx_report.bin --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --out sgx_evidence.bin --endorsements sgx_endorsements.bin --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --quote-proc in --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --quote-proc out --verify
                           popd
                           """
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", compiler, task, runArgs)

                def ec_cert_created = fileExists 'build/tests/host_verify/host/sgx_cert_ec.der'
                def rsa_cert_created = fileExists 'build/tests/host_verify/host/sgx_cert_rsa.der'
                def report_created = fileExists 'build/tests/host_verify/host/sgx_report.bin'
                def evidence_created = fileExists 'build/tests/host_verify/host/sgx_evidence.bin'
                if (ec_cert_created) {
                    println("EC cert file created successfully!")
                } else {
                    error("Failed to create EC cert file.")
                }
                if (rsa_cert_created) {
                    println("RSA cert file created successfully!")
                } else {
                    error("Failed to create RSA cert file.")
                }
                if (report_created) {
                    println("SGX report file created successfully!")
                } else {
                    error("Failed to create SGX report file.")
                }
                if (evidence_created) {
                    println("SGX evidence file created successfully!")
                } else {
                    error("Failed to create SGX evidence file.")
                }

                stash includes: 'build/tests/host_verify/host/*.der,build/tests/host_verify/host/*.bin', name: "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
            }
        }
    }

    /* Compile the tests and unstash the certs over for verification.  */
    stage("Linux nonSGX Verify Quote") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                def cmakeArgs = "-G Ninja -DBUILD_ENCLAVES=OFF -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
                def runArgs = "--user root:root --cap-add=SYS_PTRACE"
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ctest -R host_verify --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}
                           """
                // Note: Include the commands to build and run the quote verification test above
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }

    /* Windows nonSGX stage. */
    stage("Windows nonSGX Verify Quote") {
        node(globalvars.AGENTS_LABELS["windows-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                def cmakeArgs = "-G Ninja -DBUILD_ENCLAVES=OFF -DCMAKE_BUILD_TYPE=${build_type} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -Wdev"
                dir('build') {
                    withCredentials([
                        string(credentialsId: 'thim-tdx-base-url', variable: 'AZDCAP_BASE_CERT_URL_TDX'),
                        string(credentialsId: 'thim-tdx-region-url', variable: 'AZDCAP_REGION_URL')
                    ]) {
                        bat(
                            returnStdout: false,
                            returnStatus: false,
                            script: """
                                call vcvars64.bat x64
                                ${helpers.ninjaBuildCommand(cmakeArgs)}
                                ctest.exe -V -C ${build_type} -R host_verify --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS} || exit !ERRORLEVEL!
                            """
                        )
                    }
                }
            }
        }
    }
}

/* Test OE host verification with an OE package installation.
 * This will generate the necessary certs on Ubuntu and then
 * verify on another Ubuntu and Windows node.
 *
 * @param version: The version of Ubuntu to use
 * @param build_type: The build type to use. Choice of: Debug, Release, or RelWithDebInfo
 * @param compiler: The compiler to use.
*/

def ACCHostVerificationPackageTest(String version, String build_type, String compiler) {
    stage("ACC-${version} Generate Quote") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = "-G Ninja -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
                def devices = helpers.getDockerSGXDevices("ubuntu", helpers.getUbuntuReleaseVer())
                def runArgs = "--user root:root --cap-add=SYS_PTRACE ${devices} --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                println("ACC-${version} running Docker container with ${devices}")
                println("Generating certificates and reports ...")
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           pushd tests/host_verify/host
                           openssl ecparam -name prime256v1 -genkey -noout -out keyec.pem
                           openssl ec -in keyec.pem -pubout -out publicec.pem
                           openssl genrsa -out keyrsa.pem 2048
                           openssl rsa -in keyrsa.pem -outform PEM -pubout -out publicrsa.pem
                           ../../../output/bin/oeutil gen --format cert keyec.pem publicec.pem --out sgx_cert_ec.der --verify
                           ../../../output/bin/oeutil gen --format cert keyrsa.pem publicrsa.pem --out sgx_cert_rsa.der --verify
                           ../../../output/bin/oeutil gen --format legacy_report_remote --out sgx_report.bin --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --out sgx_evidence.bin --endorsements sgx_endorsements.bin --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --quote-proc in --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --quote-proc out --verify
                           popd
                           """
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", compiler , task, runArgs)

                def ec_cert_created = fileExists 'build/tests/host_verify/host/sgx_cert_ec.der'
                def rsa_cert_created = fileExists 'build/tests/host_verify/host/sgx_cert_rsa.der'
                def report_created = fileExists 'build/tests/host_verify/host/sgx_report.bin'
                def evidence_created = fileExists 'build/tests/host_verify/host/sgx_evidence.bin'
                if (ec_cert_created) {
                    println("EC cert file created successfully!")
                } else {
                    error("Failed to create EC cert file.")
                }
                if (rsa_cert_created) {
                    println("RSA cert file created successfully!")
                } else {
                    error("Failed to create RSA cert file.")
                }
                if (report_created) {
                    println("SGX report file created successfully!")
                } else {
                    error("Failed to create SGX report file.")
                }
                if (evidence_created) {
                    println("SGX evidence file created successfully!")
                } else {
                    error("Failed to create SGX evidence file.")
                }

                stash includes: 'build/tests/host_verify/host/*.der,build/tests/host_verify/host/*.bin', name: "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
            }
        }
    }

    /* Linux nonSGX stage. */
    stage("Linux nonSGX Verify Quote") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                def cmakeArgs = "-G Ninja \
                             -DBUILD_ENCLAVES=OFF \
                             -DCMAKE_BUILD_TYPE=${build_type} \
                             -DCMAKE_INSTALL_PREFIX=/opt/openenclave \
                             -DCOMPONENT=OEHOSTVERIFY \
                             -Wdev"
                def cmakeArgsHostVerify = "-G Ninja \
                                       -DBUILD_ENCLAVES=OFF \
                                       -DCMAKE_BUILD_TYPE=${build_type} \
                                       -Wdev"
                def runArgs = "--user root:root --cap-add=SYS_PTRACE"
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           cpack -G DEB -D CPACK_DEB_COMPONENT_INSTALL=ON -D CPACK_COMPONENTS_ALL=OEHOSTVERIFY
                           if [ -d /opt/openenclave ]; then sudo rm -r /opt/openenclave; fi
                           sudo dpkg -i open-enclave-hostverify*.deb
                           cp tests/host_verify/host/*.der ${WORKSPACE}/samples/host_verify
                           cp tests/host_verify/host/*.bin ${WORKSPACE}/samples/host_verify
                           pushd ${WORKSPACE}/samples/host_verify
                           if [ ! -d build ]; then mkdir build; fi
                           cd build
                           ${helpers.ninjaBuildCommand(cmakeArgs, "..")}
                           ./host_verify -r ../sgx_report.bin
                           ./host_verify -c ../sgx_cert_ec.der
                           ./host_verify -c ../sgx_cert_rsa.der
                           popd
                           """
                // Note: Include the commands to build and run the quote verification test above
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }

    /* Windows nonSGX stage. */
    stage("Windows nonSGX Verify Quote") {
        node(globalvars.AGENTS_LABELS["windows-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                cmakeArgs = "-G Ninja \
                             -DBUILD_ENCLAVES=OFF \
                             -DCMAKE_BUILD_TYPE=${build_type} \
                             -DCOMPONENT=OEHOSTVERIFY \
                             -DCPACK_GENERATOR=NuGet \
                             -DNUGET_PACKAGE_PATH=C:/oe_prereqs \
                             -Wdev"
                cmakeArgsHostVerify = "-G Ninja \
                                       -DBUILD_ENCLAVES=OFF \
                                       -DCMAKE_BUILD_TYPE=${build_type} \
                                       -DCMAKE_PREFIX_PATH=C:/openenclave/lib/openenclave/cmake \
                                       -DNUGET_PACKAGE_PATH=C:/oe_prereqs \
                                       -Wdev"
                dir('build') {
                    bat(
                        returnStdout: false,
                        returnStatus: false,
                        script: """
                            call vcvars64.bat x64
                            ${helpers.ninjaBuildCommand(cmakeArgs)}
                            cpack -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
                            copy tests\\host_verify\\host\\*.der ${WORKSPACE}\\samples\\host_verify
                            copy tests\\host_verify\\host\\*.bin ${WORKSPACE}\\samples\\host_verify
                            if exist C:\\oe (rmdir C:\\oe)
                            nuget.exe install open-enclave.OEHOSTVERIFY -Source ${WORKSPACE}\\build -OutputDirectory C:\\oe -ExcludeVersion
                            xcopy /E C:\\oe\\open-enclave.OEHOSTVERIFY\\OEHOSTVERIFY\\openenclave C:\\openenclave\\
                            pushd ${WORKSPACE}\\samples\\host_verify
                            if not exist build\\ (mkdir build)
                            cd build
                            ${helpers.ninjaBuildCommand(cmakeArgsHostVerify, "..")}
                            host_verify.exe -r ../sgx_report.bin
                            host_verify.exe -c ../sgx_cert_ec.der
                            host_verify.exe -c ../sgx_cert_rsa.der
                            popd
                            """
                    )
                }
            }
        }
    }
}

/* Tests OE Release packages
 *
 * @param label: Label of the node to run the test on
 * @param release_version: Version of the OE release to test
 * @param oe_package: Name of the OE package to test
 * @param source: Source to obtain the OE package from
 * @param storage_credentials_id: ID of the credentials to access the Azure storage account
 * @param storage_blob: Name of the Azure storage blob to download the OE package from
 * @param lvi_mitigation: Whether to test with LVI mitigation
 */
def OEReleaseTest(String label, String release_version, String oe_package = "open-enclave", String source = "Azure", String storage_credentials_id, String storage_blob, boolean lvi_mitigation = false) {
    stage("OE Release Test ${label}") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.releaseInstall(release_version, oe_package, source, storage_credentials_id, storage_blob)
                helpers.TestSamplesCommand(lvi_mitigation, oe_package)
            }
        }
    }
}

/* Tests Intel RCs
 *
 * @param label: Label of the node to run the test on
 * @param release_version: Version of the OE release to test
 * @param oe_package: Name of the OE package to test
 * @param source: Source to obtain the OE package from
 * @param lvi_mitigation: Whether to test with LVI mitigation
 * @param dcap_url: URL of the DCAP package to install
 * @param local_repository_name: Name of the local repository to install
 * @param install_flags: Flags to pass to the install script
 */
def TestIntelRCs(String label, String release_version, String oe_package = "open-enclave", String source = "GitHub", boolean lvi_mitigation = false, String dcap_url = "", String local_repository_name = "", String install_flags = "") {
    stage("Test Intel Drivers RCs ${label}") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def local_repository_path = ""
                if (local_repository_name) {
                    helpers.azureContainerDownload('intelreleasecandidates', local_repository_name, 'jenkins-private-intel-release-candidates')
                    sh "tar xzf ${local_repository_name} --directory=${WORKSPACE}"
                    local_repository_path = "${WORKSPACE}/sgx_debian_local_repo"
                }
                helpers.dependenciesInstall(dcap_url, local_repository_path, install_flags)
                helpers.releaseInstall(release_version, oe_package, source)
                helpers.TestSamplesCommand(lvi_mitigation, oe_package)
            }
        }
    }
}

// Azure Windows

def windowsPrereqsVerify(String label) {
    stage("Windows ${label} Install Prereqs Verification") {
        node(globalvars.AGENTS_LABELS[label]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                dir('scripts') {
                    bat(
                        returnStdout: false,
                        returnStatus: false,
                        script: """
                            powershell.exe -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File install-windows-prereqs.ps1 -InstallPath C:\\oe_prereqs -LaunchConfiguration SGX1FLC-NoIntelDrivers -DCAPClientType Azure -VerificationOnly
                        """
                    )
                }
            }
        }
    }
}

def windowsLinuxElfBuild(String windows_label, String ubuntu_label, String compiler, String build_type, String lvi_mitigation = 'None', String lvi_mitigation_skip_tests = 'OFF', List extra_cmake_args = []) {
    stage("${ubuntu_label} ${compiler} ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node(ubuntu_label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def runArgs = "--user root:root --cap-add=SYS_PTRACE"
                def task = """
                           cmake ${WORKSPACE}                                           \
                               -G Ninja                                                 \
                               -DCMAKE_BUILD_TYPE=${build_type}                         \
                               -DLVI_MITIGATION=${lvi_mitigation}                       \
                               -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin    \
                               -DLVI_MITIGATION_SKIP_TESTS=${lvi_mitigation_skip_tests} \
                               -Wdev                                                    \
                               ${extra_cmake_args.join(' ')}
                           ninja -v
                           """
                if (! ubuntu_label.contains("2004")) {
                    println("Unable to determine version from Ubuntu agent label. Defaulting to Ubuntu 20.04")
                }
                def imageName = "oetools-20.04"
                common.ContainerRun("${imageName}:${DOCKER_TAG}", compiler, task, runArgs)
                sh 'sudo chown -R oeadmin:oeadmin ${WORKSPACE}/build/tests'
                stash includes: 'build/tests/**', name: "linux-${windows_label}-${compiler}-${build_type}-lvi_mitigation=${lvi_mitigation}-${ubuntu_label}-${BUILD_NUMBER}"
            }
        }
    }
    stage("${windows_label} ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node(windows_label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux-${windows_label}-${compiler}-${build_type}-lvi_mitigation=${lvi_mitigation}-${ubuntu_label}-${BUILD_NUMBER}"
                bat 'move build linuxbin'
                dir('build') {
                    bat(
                        returnStdout: false,
                        returnStatus: false,
                        script: """
                            call vcvars64.bat x64
                            setlocal EnableDelayedExpansion
                            cmake.exe ${WORKSPACE} -G Ninja -DADD_WINDOWS_ENCLAVE_TESTS=ON -DBUILD_ENCLAVES=OFF -DCMAKE_BUILD_TYPE=${build_type} -DLINUX_BIN_DIR=${WORKSPACE}\\linuxbin\\tests -DLVI_MITIGATION=${lvi_mitigation} -DLVI_MITIGATION_SKIP_TESTS=${lvi_mitigation_skip_tests} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -Wdev || exit !ERRORLEVEL!
                            ninja -v || exit !ERRORLEVEL!
                            ctest.exe -V -C ${build_type} --timeout ${globalvars.CTEST_TIMEOUT_SECONDS} || exit !ERRORLEVEL!
                        """
                    )
                }
            }
        }
    }
}

def windowsCrossCompile(String label, String compiler, String build_type, String lvi_mitigation = 'None', String OE_SIMULATION = "0", String lvi_mitigation_skip_tests = 'OFF', List extra_cmake_args = []) {
    stage("Windows ${label} ${build_type} with SGX LVI_MITIGATION=${lvi_mitigation}") {
        // fail fast and retry if Windows agent goes offline
        // exceptions seen in the wild:
        // 1. java.io.IOException
        // 2. org.jenkinsci.plugins.workflow.steps.FlowInterruptedException
        // 3. java.org.InterruptedException
        int max_try_count = 3
        int try_count = 1
        retry(count: max_try_count) {
            try {
                node("${label}-${compiler}") {
                    // Interrupt build if no output received from node for 15 minutes
                    timeout(time: 15, activity: true, unit: 'MINUTES') {
                        withEnv(["OE_SIMULATION=${OE_SIMULATION}"]) {
                            common.WinCompilePackageTest("build/X64-${build_type}", build_type, 'OFF', globalvars.CTEST_TIMEOUT_SECONDS, lvi_mitigation, lvi_mitigation_skip_tests, extra_cmake_args)
                        }
                    }
                }
            }
            catch(org.jenkinsci.plugins.workflow.steps.FlowInterruptedException e) {
                println("Caught FlowInterruptedException")
                // FlowInterruptedException can be caused by timeouts, aborts, or 
                // graceful agent disconnections. We only want to retry on timeouts
                // all other FlowInterruptionException causes should abort the stage.
                if(e.getCauses()[0].toString() ==~ /.*(t|T)imeout.*/) {
                    println("An abort was caused by a known agent issue.")
                    try_count = try_count + 1
                    helpers.check_if_retry(max_try_count, try_count)
                    throw e
                }
            }
            catch(InterruptedException e) {
                println("Caught InterruptedException")
                // Thread interruptions caused by unexpected or abrupt agent disconnection
                // will cause this exception. This case should be retried.
                println("An abort was caused by a known agent issue.")
                try_count = try_count + 1
                helpers.check_if_retry(max_try_count, try_count)
                throw e
            }
            catch(IOException e) {
                println("Caught IOException")
                // Unexpected termination of the channel with the agent will cause
                // this exception. This case should be retried.
                println("An abort was caused by a known agent issue.")
                try_count = try_count + 1
                helpers.check_if_retry(max_try_count, try_count)
                throw e
            }
            catch(e) {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    error("Caught exception: ${e}")
                }
            }
        }
    }
}

def windowsCrossPlatform(String label) {
    stage("Windows ${label} Cross Plaform Build") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm

                dir("devex/cross-nuget/standalone-builds/windows") {
                    bat(
                        returnStdout: false,
                        returnStatus: false,
                        script: """
                            vcvars64.bat x64 && powershell -c "Set-ExecutionPolicy Bypass -Scope Process; .\\build.ps1 -SDK_PATH ${WORKSPACE}"
                            vcvars64.bat x64 && powershell -c "Set-ExecutionPolicy Bypass -Scope Process; .\\pack.ps1"
                        """
                    )
                }
            }
        }
    }
}


// Agnostic Linux

def simulationContainerTest(String version, String build_type, String compiler, List extra_cmake_args = []) {
    stage("Simulation Ubuntu ${version} clang-${compiler} ${build_type}, extra_cmake_args: ${extra_cmake_args}") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def runArgs = "--user root:root --cap-add=SYS_PTRACE"
                def task = """
                           cmake ${WORKSPACE}                                           \
                               -G Ninja                                                 \
                               -DCMAKE_BUILD_TYPE=${build_type}                         \
                               -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin    \
                               ${extra_cmake_args.join(' ')}                            \
                               -Wdev
                           ninja -v
                           ctest --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}
                           """
                withEnv(["OE_SIMULATION=1"]) {
                    common.ContainerRun("oetools-${version}:${DOCKER_TAG}", compiler, task, runArgs)
                }
            }
        }
    }
}

def buildCrossPlatform(String version, String compiler) {
    stage("Ubuntu ${version} OP-TEE Build") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def runArgs = "--user root:root --cap-add=SYS_PTRACE"
                def os = version == "20.04" ? "focal" : "bionic"
                def task = """
                           cd ${WORKSPACE}

                           sdk_path=\$(pwd)
                           export OE_SDK_PATH=\${sdk_path}
                           export BUILD_PATH=\${sdk_path}/build
                           export OPTEE_BUILD_PATH=\${sdk_path}/build/optee
                           export PACK_PATH=\${sdk_path}/path
                           export OS_CODENAME=${os}

                           sudo ansible-playbook scripts/ansible/oe-contributors-setup-cross-arm.yml
                           sudo apt install python python3-pyelftools p7zip-full -y

                           bash devex/cross-nuget/standalone-builds/linux/build-optee.sh
                           bash devex/cross-nuget/standalone-builds/linux/runner.sh
                           """

                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }
}

def AArch64GNUTest(String version, String build_type) {
    stage("AArch64 GNU gcc Ubuntu${version} ${build_type}") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def runArgs = "--user root:root --cap-add=SYS_PTRACE"
                def task = """
                            cmake ${WORKSPACE}                                                     \
                                -G Ninja                                                           \
                                -DCMAKE_BUILD_TYPE=${build_type}                                   \
                                -DCMAKE_TOOLCHAIN_FILE=${WORKSPACE}/cmake/arm-cross.cmake          \
                                -DOE_TA_DEV_KIT_DIR=/devkits/vexpress-qemu_armv8a/export-ta_arm64  \
                                -DHAS_QUOTE_PROVIDER=OFF                                           \
                                -Wdev
                            ninja -v
                            """
                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", "cross", task, runArgs)
            }
        }
    }
}

def checkDevFlows(String version, String compiler) {
    stage('Default compiler') {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def runArgs = "--user root:root --cap-add=SYS_PTRACE"
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DHAS_QUOTE_PROVIDER=OFF -Wdev --warn-uninitialized -Werror=dev
                           ninja -v
                           """
                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }
}

def checkCI(String compiler) {
    stage('Check CI') {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-20.04"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def runArgs = "--user root:root --cap-add=SYS_PTRACE"
                def task = """
                    git config --global --add safe.directory ${WORKSPACE}
                    cd ${WORKSPACE}
                    ./scripts/check-ci
                """
                // At the moment, the check-ci script assumes that it's executed from the
                // root source code directory.
                common.ContainerRun("oetools-20.04:${DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }
}


// Packaging

def LinuxPackaging(String node_label, String compiler, String build_type, String lvi_mitigation = 'None') {
    stage("${node_label} ${compiler} Package ${build_type} LVI ${lvi_mitigation}") {
        node("${node_label}") {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE}                               \
                             -DCMAKE_BUILD_TYPE=${build_type}               \
                             -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave' \
                             -DCPACK_GENERATOR=DEB                          \
                             -DLVI_MITIGATION=${lvi_mitigation}             \
                             -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin
                           make
                           cpack -D CPACK_DEB_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
                           cpack
                           ctest --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}
                           """
                common.Run(compiler, task)
            }
        }
    }
}

def WindowsPackaging(String node_label, String compiler, String build_type, String lvi_mitigation = 'None', String simulation = '1') {
    stage("WS2019 ${compiler} ${build_type} LVI ${lvi_mitigation}") {
        node("${node_label}-${compiler}") {
            withEnv(["OE_SIMULATION=${simulation}"]) {
                timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                    common.WinCompilePackageTest("build", build_type, "ON", globalvars.CTEST_TIMEOUT_SECONDS, lvi_mitigation)
                }
            }
        }
    }
}
