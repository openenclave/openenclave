// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*************************************
* Shared Library for OpenEnclave Tests
*************************************/

// Azure Linux

/* Builds and runs code coverage tests for OE on Ubuntu
 *
 * @param version    [string] The Ubuntu version to use
 * @param compiler   [string] The compiler to use
 * @param build_type [string] The cmake build type to use.
 *                                Choice of: Debug, Release, or RelWithDebInfo
 * @param pr_id      [string] Optional - to checkout a specific oe pull request merge head
 */
def ACCCodeCoverageTest(String version, String compiler, String build_type, String pr_id = '') {
    stage("ACC ${version} ${compiler} ${build_type} Code Coverage") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def cmakeArgs = helpers.CmakeArgs(
                    builder: 'Ninja',
                    build_type: build_type,
                    code_coverage: true,
                    debug_malloc: false,
                    lvi_mitigation: 'None',
                    lvi_mitigation_skip_tests: true,
                    use_snmalloc: false,
                    use_eeid: false)
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
 * @param label                      [string]  the label of the Jenkins agent to use
 * @param compiler                   [string]  the compiler to use
 * @param build_type                 [string]  cmake build type to use. 
 *                                             Choice of: Debug, Release, or RelWithDebInfo
 * @param lvi_mitigation             [string]  build enclave libraries with LVI mitigation. 
 *                                             Choice of: None, ControlFlow-GNU, ControlFlow-Clang, or ControlFlow
 * @param lvi_mitigation_skip_tests  [boolean] skip LVI mitigation tests?
 * @param use_snmalloc               [boolean] use snmalloc allocator?
 * @param use_eeid                   [boolean] use EEID?
 * @param fresh_install              [boolean] start with a plain VM and install OE dependencies?
 * @param pr_id                      [string]  Optional - to checkout a specific oe pull request merge head
 */
def ACCTest(String label, String compiler, String build_type, String lvi_mitigation, boolean lvi_mitigation_skip_tests = false, boolean use_snmalloc = false, boolean use_eeid = false, boolean fresh_install = false, String pr_id = '') {
    stage("${label} ${compiler} ${build_type} ${lvi_mitigation} ${fresh_install ? ", e2e" : ""} SNMALLOC=${use_snmalloc} EEID=${use_eeid}") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
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
                def cmakeArgs = helpers.CmakeArgs(
                    builder: 'Ninja',
                    build_type: build_type,
                    code_coverage: false,
                    debug_malloc: false,
                    lvi_mitigation: lvi_mitigation,
                    lvi_mitigation_skip_tests: lvi_mitigation_skip_tests,
                    use_snmalloc: use_snmalloc,
                    use_eeid: use_eeid)
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
 * @param version                   [string]  the Ubuntu version to use
 * @param compiler                  [string]  the compiler to use
 * @param lvi_mitigation            [string]  build enclave libraries with LVI mitigation.
 *                                            Choice of: None, ControlFlow-GNU, ControlFlow-Clang, or ControlFlow
 * @param lvi_mitigation_skip_tests [boolean] skip LVI mitigation tests?
 * @param pr_id                     [string]  Optional - to checkout a specific oe pull request merge head
 */
def ACCUpgradeTest(String version, String compiler, String lvi_mitigation, boolean lvi_mitigation_skip_tests = false, String pr_id = '') {
    stage("ACC Upgrade ${version} RelWithDebInfo ${lvi_mitigation} LVI_MITIGATION_SKIP_TESTS=${lvi_mitigation_skip_tests}") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def cmakeArgs = helpers.CmakeArgs(
                    builder: 'Ninja',
                    build_type: 'RelWithDebInfo',
                    code_coverage: false,
                    debug_malloc: false,
                    lvi_mitigation: lvi_mitigation,
                    lvi_mitigation_skip_tests: lvi_mitigation_skip_tests,
                    use_snmalloc: false,
                    use_eeid: false)
                println "Install latest open-enclave release"
                helpers.releaseInstall("latest", "open-enclave", "GitHub")
                helpers.TestSamplesCommand()
                println "Build and install current open-enclave build"
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ${helpers.TestCommand()}
                           ${helpers.ninjaInstallCommand()}
                           """
                common.Run(compiler, task)
                helpers.TestSamplesCommand()
            }
        }
    }
}

/* Tests building and running OE in a container environment
 *
 * @param version                   [string]  the Ubuntu version to use
 * @param compiler                  [string]  the compiler to use
 * @param lvi_mitigation            [string]  build enclave libraries with LVI mitigation.
 *                                            Choice of: None, ControlFlow-GNU, ControlFlow-Clang, or ControlFlow
 * @param lvi_mitigation_skip_tests [boolean] skip LVI mitigation tests?
 * @param pr_id                     [string]  Optional - to checkout a specific oe pull request merge head
 */
def ACCContainerTest(String version, String compiler, String lvi_mitigation, boolean lvi_mitigation_skip_tests = false, String pr_id = '') {
    stage("ACC Container ${version} RelWithDebInfo ${lvi_mitigation} LVI_MITIGATION_SKIP_TESTS=${lvi_mitigation_skip_tests}") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def cmakeArgs = helpers.CmakeArgs(
                    builder: 'Ninja',
                    build_type: 'RelWithDebInfo',
                    code_coverage: false,
                    debug_malloc: false,
                    lvi_mitigation: lvi_mitigation,
                    lvi_mitigation_skip_tests: lvi_mitigation_skip_tests,
                    use_snmalloc: false,
                    use_eeid: false)
                def devices = helpers.getDockerSGXDevices("ubuntu", helpers.getUbuntuReleaseVer())
                def runArgs = "--cap-add=SYS_PTRACE ${devices} --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
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
 * @param version                    [string]  the version of the container to use
 * @param build_type                 [string]  cmake build type to use.
 *                                             Choice of: Debug, Release, or RelWithDebInfo
 * @param lvi_mitigation             [string]  build enclave libraries with LVI mitigation.
 *                                             Choice of: None, ControlFlow-GNU, ControlFlow-Clang, or ControlFlow
 * @param lvi_mitigation_skip_tests  [boolean] skip LVI mitigation tests?
 * @param use_snmalloc               [boolean] use snmalloc allocator?
 * @param pr_id                      [string]  Optional - to checkout a specific oe pull request merge head
 */
def ACCPackageTest(String version, String build_type, String lvi_mitigation, boolean lvi_mitigation_skip_tests = 'OFF', boolean use_snmalloc = 'OFF', String pr_id = '') {
    stage("ACC Package ${version} ${build_type} ${lvi_mitigation} LVI_MITIGATION_SKIP_TESTS=${lvi_mitigation_skip_tests} SNMALLOC=${use_snmalloc}") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def cmakeArgs = helpers.CmakeArgs(
                    builder: 'CMake',
                    build_type: build_type,
                    code_coverage: false,
                    debug_malloc: false,
                    lvi_mitigation: lvi_mitigation,
                    lvi_mitigation_skip_tests: lvi_mitigation_skip_tests,
                    use_snmalloc: use_snmalloc,
                    use_eeid: false)
                def devices = helpers.getDockerSGXDevices("ubuntu", helpers.getUbuntuReleaseVer())
                println("Running Docker container with ${devices}")
                common.ContainerRun(
                    "oetools-${version}:${params.DOCKER_TAG}",
                    globalvars.COMPILER,
                    """
                        ${helpers.makeBuildCommand(cmakeArgs)}
                        ${helpers.createOpenEnclavePackageCommand()}
                        ${helpers.createHostVerifyPackageCommand()}
                        ${helpers.makeInstallCommand()}
                        ${helpers.TestCommand()}
                    """,
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
 * @param version     [string] The version of the container to use
 * @param build_type  [string] The build type to use
 * @param compiler    [string] The compiler to use
 * @param pr_id       [string] Optional - to checkout a specific oe pull request merge head
 */
def ACCHostVerificationTest(String version, String build_type, String compiler, String pr_id = '') {
    stage("ACC ${version} Generate Quote") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def cmakeArgs = "-G Ninja -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
                def devices = helpers.getDockerSGXDevices("ubuntu", helpers.getUbuntuReleaseVer())
                def runArgs = "--cap-add=SYS_PTRACE ${devices} --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                println("ACC-${version} running Docker container with ${devices}")
                println("Generating certificates and reports ...")
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           cd tests/host_verify/host
                           openssl ecparam -name prime256v1 -genkey -noout -out keyec.pem
                           openssl ec -in keyec.pem -pubout -out publicec.pem
                           openssl genrsa -out keyrsa.pem 2048
                           openssl rsa -in keyrsa.pem -outform PEM -pubout -out publicrsa.pem
                           while \$try -lt 10; do
                             ../../../output/bin/oeutil gen --format cert keyec.pem publicec.pem --out sgx_cert_ec.der --verify
                             if [ ! -f sgx_cert_ec.der ]; then
                                 try=$((try + 1))
                                 sleep 5
                             else
                                 break
                             fi
                           done
                           ../../../output/bin/oeutil gen --format cert keyrsa.pem publicrsa.pem --out sgx_cert_rsa.der --verify
                           ../../../output/bin/oeutil gen --format legacy_report_remote --out sgx_report.bin --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --out sgx_evidence.bin --endorsements sgx_endorsements.bin --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --quote-proc in --verify
                           ../../../output/bin/oeutil gen --format sgx_ecdsa --quote-proc out --verify
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
                helpers.oeCheckoutScm(pr_id)
                unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                def cmakeArgs = "-G Ninja -DBUILD_ENCLAVES=OFF -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
                def runArgs = "--cap-add=SYS_PTRACE"
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ctest -R host_verify --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS} || ctest --rerun-failed --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}
                           """
                // Note: Include the commands to build and run the quote verification test above
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }

    /* Windows 2022 nonSGX stage. */
    stage("Windows nonSGX Verify Quote") {
        node(globalvars.AGENTS_LABELS["ws2022-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                def cmakeArgs = "-G Ninja -DBUILD_ENCLAVES=OFF -DCMAKE_BUILD_TYPE=${build_type} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -Wdev"
                dir('build') {
                    withCredentials([
                        string(credentialsId: 'thim-tdx-base-url', variable: 'AZDCAP_BASE_CERT_URL_TDX'),
                        string(credentialsId: 'thim-tdx-region-url', variable: 'AZDCAP_REGION_URL')
                    ]) {
                        helpers.ninjaBuildCommand(cmakeArgs)
                        bat(
                            script: """
                                call vcvars64.bat x64
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
 * @param version     [string] The version of Ubuntu to use
 * @param build_type  [string] The build type to use.
 *                             Choice of: Debug, Release, or RelWithDebInfo
 * @param compiler    [string] The compiler to use.
 * @param pr_id       [string] Optional - to checkout a specific oe pull request merge head
 */

def ACCHostVerificationPackageTest(String version, String build_type, String compiler, String pr_id = '') {
    stage("ACC-${version} Generate Quote") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def cmakeArgs = "-G Ninja -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
                def devices = helpers.getDockerSGXDevices("ubuntu", helpers.getUbuntuReleaseVer())
                def runArgs = "--cap-add=SYS_PTRACE ${devices} --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
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
                helpers.oeCheckoutScm(pr_id)
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
                def runArgs = "--cap-add=SYS_PTRACE"
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
        node(globalvars.AGENTS_LABELS["ws2022-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
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
                boolean PACKAGE_BUILT = false
                dir("${WORKSPACE}\\build") {
                    if ( PACKAGE_BUILT ) {
                        unstash "windows_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                    } else {
                        helpers.ninjaBuildCommand(cmakeArgs)
                        bat(
                            script: """
                                call vcvars64.bat x64
                                cpack -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
                            """
                        )
                        stash includes: '*.nupkg,tests\\host_verify\\host\\*.bin,tests\\host_verify\\host\\*.der', 
                              name: "windows_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                        PACKAGE_BUILT = true
                    }
                    bat(
                        script: """
                            copy tests\\host_verify\\host\\*.der ${WORKSPACE}\\samples\\host_verify
                            copy tests\\host_verify\\host\\*.bin ${WORKSPACE}\\samples\\host_verify
                            if exist C:\\oe (rmdir C:\\oe)
                            nuget.exe install open-enclave.OEHOSTVERIFY -Source ${WORKSPACE}\\build -OutputDirectory C:\\oe -ExcludeVersion
                            xcopy /E C:\\oe\\open-enclave.OEHOSTVERIFY\\OEHOSTVERIFY\\openenclave C:\\openenclave\\
                        """
                    )
                }
                dir("${WORKSPACE}\\samples\\host_verify") {
                    bat(
                        script: """
                            if not exist build\\ (mkdir build)
                        """
                    )
                }
                dir("${WORKSPACE}\\samples\\host_verify\\build") {
                    helpers.ninjaBuildCommand(cmakeArgsHostVerify, "..")
                    bat(
                        script: """
                            .\\host_verify.exe -r ../sgx_report.bin
                            .\\host_verify.exe -c ../sgx_cert_ec.der
                            .\\host_verify.exe -c ../sgx_cert_rsa.der
                        """
                    )
                }
            }
        }
    }
}

/* Tests OE Release packages
 *
 * @param label                  [string]  Label of the node to run the test on
 * @param release_version        [string]  Version of the OE release to test
 * @param oe_package             [string]  Name of the OE package to test
 *                                         Choice of: open-enclave, or open-enclave-hostverify
 * @param source                 [string]  Source to obtain the OE package from
 *                                         Choice of: Azure, or GitHub
 * @param storage_credentials_id [string]  ID of the credentials to access the Azure storage account
 * @param storage_blob           [string]  Name of the Azure storage blob to download the OE package from
 * @param lvi_mitigation         [boolean] Build enclave libraries with LVI mitigation.
 *                                         TODO: This and helpers.testSamples* should be converted into string to allow for the different mitigation options
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
 * @param label                 [string]  Label of the node to run the test on
 * @param release_version       [string]  Version of the OE release to test
 * @param oe_package            [string]  Name of the OE package to test
 *                                        Choice of: open-enclave, or open-enclave-hostverify
 * @param source                [string]  Source to obtain the OE package from
 *                                        Choice of: Azure, or GitHub
 * @param lvi_mitigation        [string]  Build enclave libraries with LVI mitigation.
 *                                        Choice of: None, ControlFlow-GNU, ControlFlow-Clang, or ControlFlow
 * @param dcap_url              [string]  URL of the DCAP package to install
 * @param local_repository_name [string]  Name of the local repository to install
 * @param install_flags         [string]  Flags to pass to the install script
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

def windowsPrereqsVerify(String label, String pr_id = '') {
    stage("Windows ${label} Install Prereqs Verification") {
        node(globalvars.AGENTS_LABELS[label]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
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

/* Precompiles ELF enclave on Linux and run on Windows
 *
 * @param windows_label              [string]  Label of the Windows node to run the test on
 * @param ubuntu_label               [string]  Label of the Ubuntu node to run the test on
 * @param compiler                   [string]  Compiler to use
 * @param build_type                 [string]  The build type to use.
 *                                             Choice of: Debug, Release, or RelWithDebInfo
 * @param lvi_mitigation             [string]  build enclave libraries with LVI mitigation.
 *                                             Choice of: None, ControlFlow-GNU, ControlFlow-Clang, or ControlFlow
 * @param lvi_mitigation_skip_tests  [boolean] Whether to skip LVI mitigation tests
 * @param extra_cmake_args           [string]  Add custom cmake args
 * @param pr_id                      [string]  Optional - to checkout a specific oe pull request merge head
 */
def windowsLinuxElfBuild(String windows_label, String ubuntu_label, String compiler, String build_type, String lvi_mitigation = 'None', String lvi_mitigation_skip_tests = 'OFF', List extra_cmake_args = [], String pr_id = '') {
    stage("${ubuntu_label} ${compiler} ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node(ubuntu_label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def runArgs = "--cap-add=SYS_PTRACE"
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
                helpers.oeCheckoutScm(pr_id)
                unstash "linux-${windows_label}-${compiler}-${build_type}-lvi_mitigation=${lvi_mitigation}-${ubuntu_label}-${BUILD_NUMBER}"
                bat 'move build linuxbin'
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
                                setlocal EnableDelayedExpansion
                                cmake.exe ${WORKSPACE} -G Ninja -DADD_WINDOWS_ENCLAVE_TESTS=ON -DBUILD_ENCLAVES=OFF -DCMAKE_BUILD_TYPE=${build_type} -DLINUX_BIN_DIR=${WORKSPACE}\\linuxbin\\tests -DLVI_MITIGATION=${lvi_mitigation} -DLVI_MITIGATION_SKIP_TESTS=${lvi_mitigation_skip_tests} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -Wdev || exit !ERRORLEVEL!
                                ninja -v || exit !ERRORLEVEL!
                                ctest.exe -V -C ${build_type} --timeout ${ globalvars.CTEST_TIMEOUT_SECONDS * 2.2 } || exit !ERRORLEVEL!
                            """
                        )
                    }
                }
            }
        }
    }
}

/* Compile open-enclave on Windows platform, generate NuGet package out of it, 
 * install the generated NuGet package, and run samples tests against the installation.
 *
 * @param label                      [string]  Label of the Windows node to run the test on
 * @param compiler                   [string]  Compiler to use
 * @param build_type                 [string]  The build type to use.
 *                                             Choice of: Debug, Release, or RelWithDebInfo
 * @param lvi_mitigation             [string]  build enclave libraries with LVI mitigation.
 *                                             Choice of: None, ControlFlow-GNU, ControlFlow-Clang, or ControlFlow
 * @param OE_SIMULATION              [string]  Whether to run in simulation mode.
 *                                             Choice of: 0, 1
 * @param lvi_mitigation_skip_tests  [boolean] Whether to skip LVI mitigation tests
 * @param extra_cmake_args           [string]  Add custom cmake args
 * @param pr_id                      [string]  Optional - to checkout a specific oe pull request merge head
 */
def windowsCrossCompile(String label, String compiler, String build_type, String lvi_mitigation = 'None', String OE_SIMULATION = "0", String lvi_mitigation_skip_tests = 'OFF', String use_snmalloc = 'OFF', String pr_id = '') {
    stage("Windows ${label} ${build_type} with SGX LVI_MITIGATION=${lvi_mitigation}") {
        // fail fast and retry if Windows agent goes offline
        // exceptions seen in the wild:
        // 1. java.io.IOException
        // 2. org.jenkinsci.plugins.workflow.steps.FlowInterruptedException
        // 3. java.org.InterruptedException
        int TRY_COUNT = 0
        int MAX_TRY_COUNT = 4
        boolean BUILD_COMPLETED 
        boolean PACKAGE_BUILT = false
        retry(count: MAX_TRY_COUNT) {
            // Reset BUILD_COMPLETED on each retry so previous failures don't skip the build step
            BUILD_COMPLETED = false
            TRY_COUNT += 1
            try {
                node("${label}-${compiler}") {
                    // Interrupt build if no output received from node for 15 minutes
                    timeout(time: 15, activity: true, unit: 'MINUTES') {
                        withEnv(["OE_SIMULATION=${OE_SIMULATION}"]) {
                            helpers.oeCheckoutScm(pr_id)
                            dir("build") {
                                /*
                                In simulation mode, some samples should not be ran or should run simulation mode. 
                                For items that should be skipped, see items appended to SAMPLES_LIST under the IF statement with OE_SIMULATION in:
                                https://github.com/openenclave/openenclave/blob/master/samples/test-samples.cmake#L54
                                For items that should run in simulation mode, check sample Makefiles for target `simulate`
                                SIMULATION_SKIP is a "list" of samples to skip in simulation mode.
                                SIMULATION_TEST is a "list" of samples to run in simulation mode.
                                */
                                withCredentials([
                                    string(credentialsId: 'thim-tdx-base-url', variable: 'AZDCAP_BASE_CERT_URL_TDX'),
                                    string(credentialsId: 'thim-tdx-region-url', variable: 'AZDCAP_REGION_URL')
                                ]) {
                                    if ( PACKAGE_BUILT ) {
                                        unstash "${label}-${compiler}-${build_type}-${lvi_mitigation}-${OE_SIMULATION}-${lvi_mitigation_skip_tests}-${use_snmalloc}-${BUILD_NUMBER}"
                                    } else {
                                        timeout(time: 60 , unit: 'MINUTES') {
                                            bat(
                                                script: """
                                                    call vcvars64.bat x64
                                                    cmake.exe ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${build_type} -DBUILD_ENCLAVES=ON -DLVI_MITIGATION=${lvi_mitigation} -DLVI_MITIGATION_SKIP_TESTS=${lvi_mitigation_skip_tests} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCPACK_GENERATOR=NuGet -Wdev -DUSE_SNMALLOC=${use_snmalloc}
                                                    ninja.exe
                                                    """
                                            )
                                        }
                                        BUILD_COMPLETED = true
                                        bat(
                                            script: """
                                                call vcvars64.bat x64
                                                setlocal EnableDelayedExpansion
                                                ctest.exe -V -C ${build_type} --timeout ${globalvars.CTEST_TIMEOUT_SECONDS * 3}
                                                if !ERRORLEVEL! neq 0 (
                                                    echo Retrying only if more than 10 tests failed from counting lines in Testing/Temporary/LastTestsFailed.log
                                                    if exist Testing\\Temporary\\LastTestsFailed.log (
                                                        for /f "delims=" %%i in ('type Testing\\Temporary\\LastTestsFailed.log ^| find /c /v ""') DO (
                                                            SET count=%%i
                                                        )
                                                        if !count! LSS 10 (
                                                            echo Retrying due to less than 10 tests failing
                                                            ctest --rerun-failed --output-on-failure --verbose --build-config ${build_type} --repeat after-timeout:3 --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}
                                                        )
                                                    )

                                                )
                                            """
                                        )
                                        bat(
                                            script: """
                                                call vcvars64.bat x64
                                                cpack.exe -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
                                                cpack.exe
                                            """
                                        )
                                        stash includes: '*.nupkg', name: "${label}-${compiler}-${build_type}-${lvi_mitigation}-${OE_SIMULATION}-${lvi_mitigation_skip_tests}-${use_snmalloc}-${BUILD_NUMBER}"
                                        PACKAGE_BUILT = true
                                    }
                                    // Reset BUILD_COMPLETED as samples test needs to build and run
                                    // OE package is already built and stashed, so we can skip the build step in future failures
                                    BUILD_COMPLETED = false
                                    bat(
                                        script: """
                                            call vcvars64.bat x64
                                            setlocal EnableDelayedExpansion
                                            if exist C:\\oe rmdir /s/q C:\\oe
                                            nuget.exe install open-enclave -Source %cd% -OutputDirectory C:\\oe -ExcludeVersion
                                            set CMAKE_PREFIX_PATH=C:\\oe\\open-enclave\\openenclave\\lib\\openenclave\\cmake
                                            set SIMULATION_SKIP="\\attested_tls\\attestation\\"
                                            set SIMULATION_TEST="\\debugmalloc\\helloworld\\switchless\\log_callback\\file-encryptor\\pluggable_allocator\\"
                                            cd C:\\oe\\open-enclave\\openenclave\\share\\openenclave\\samples
                                            for /d %%i in (*) do (
                                                set BUILD=1
                                                if ${OE_SIMULATION} equ 1 if "!SIMULATION_SKIP:%%~nxi=!" neq "%SIMULATION_SKIP%" set BUILD=
                                                if !BUILD! equ 1 (
                                                    cd C:\\oe\\open-enclave\\openenclave\\share\\openenclave\\samples\\"%%i"
                                                    mkdir build
                                                    cd build
                                                    cmake.exe .. -G Ninja -DNUGET_PACKAGE_PATH=C:\\oe_prereqs -DLVI_MITIGATION=${lvi_mitigation} || exit !ERRORLEVEL!
                                                    ninja.exe || exit !ERRORLEVEL!
                                                    if ${OE_SIMULATION} equ 1 if "!SIMULATION_TEST:%%~nxi=!" neq "%SIMULATION_TEST%" (
                                                        echo "Running %%i with --simulation flag" 
                                                        ninja.exe simulate || exit !ERRORLEVEL!
                                                    ) else (
                                                        ninja.exe run || exit !ERRORLEVEL!
                                                    )
                                                ) else (
                                                    echo "Skipping %%i as we are in simulation mode."
                                                )
                                            )
                                        """
                                    )
                                }
                            }
                        }
                    }
                }
            }
            catch(org.jenkinsci.plugins.workflow.steps.FlowInterruptedException e) {
                println("Caught FlowInterruptedException")
                // FlowInterruptedException can be caused by timeouts, aborts, or 
                // graceful agent disconnections. We only want to retry on agent timeouts.
                // All other FlowInterruptionException causes should fail the stage.
                println(e.getCauses()[0].toString())
                if(e.getCauses()[0].toString() ==~ /.*(t|T)imeout.*/) {
                    println("An abort was caused by a known agent issue. Retrying (try ${TRY_COUNT} of ${MAX_TRY_COUNT})")
                    throw e
                } else {
                    catchError(buildResult: 'ABORTED', stageResult: 'ABORTED') {
                        error("Caught exception: ${e}")
                    }
                }
            }
            catch(InterruptedException e) {
                println("Caught InterruptedException")
                // Thread interruptions caused by unexpected or abrupt agent disconnection
                // will cause this exception. This case should be retried.
                println("An abort was caused by a known agent issue. Retrying (try ${TRY_COUNT} of ${MAX_TRY_COUNT})")
                println(e.getCauses()[0].toString())
                throw e
            }
            catch(IOException e) {
                println("Caught IOException")
                // Unexpected termination of the channel with the agent should be retried.
                // File read/write issues in build/tests will also be caught. IOExceptions 
                // during tests should not be retried.
                if ( BUILD_COMPLETED ) {
                    println("IOException occurred but the build completed. This is likely a test failure, and will not be retried.")
                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                        error("Caught exception: ${e}")
                    }
                } else {
                    println("An exception was caused by a known issue. Retrying (try ${TRY_COUNT} of ${MAX_TRY_COUNT})")
                    if (e.getCause()) {
                        println(e.getCause().toString())
                    }
                    throw e
                }
            }
            catch(e) {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    error("Caught exception: ${e}")
                }
            }
        }
    }
}

def windowsCrossPlatform(String label, String pr_id = '') {
    stage("Windows ${label} Cross Plaform Build") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)

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

/* Builds OE in Simulation mode inside a containar
 *
 * @param version           [string]  Version of Ubuntu to use
 * @param build_type        [string]  The build type to use.
 *                                    Choice of: Debug, Release, or RelWithDebInfo
 * @param compiler          [string]  Compiler to use
 * @param extra_cmake_args  [string]  Add custom cmake args
 * @param pr_id             [string]  Optional - to checkout a specific oe pull request merge head
 */
def simulationContainerTest(String version, String build_type, String compiler, List extra_cmake_args = [], String pr_id = '') {
    stage("Simulation Ubuntu ${version} clang-${compiler} ${build_type}, extra_cmake_args: ${extra_cmake_args}") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def runArgs = "--cap-add=SYS_PTRACE"
                def task = """
                           cmake ${WORKSPACE}                                           \
                               -G Ninja                                                 \
                               -DCMAKE_BUILD_TYPE=${build_type}                         \
                               -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin    \
                               ${extra_cmake_args.join(' ')}                            \
                               -Wdev
                           ninja -v
                           ${helpers.TestCommand()}
                           """
                withEnv(["OE_SIMULATION=1"]) {
                    common.ContainerRun("oetools-${version}:${DOCKER_TAG}", compiler, task, runArgs)
                }
            }
        }
    }
}

/* Builds OP-TEE inside a container
 *
 * @param version  [string]  Version of Ubuntu to use (e.g. 20.04)
 * @param compiler [string]  Compiler to use
 * @param pr_id    [string] Optional - to checkout a specific oe pull request merge head
 */
def buildCrossPlatform(String version, String compiler, String pr_id = '') {
    stage("Ubuntu ${version} OP-TEE Build") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def runArgs = "--cap-add=SYS_PTRACE"
                def os_codename = helpers.getUbuntuCodename(version)
                def task = """
                           cd ${WORKSPACE}

                           sdk_path=\$(pwd)
                           export OE_SDK_PATH=\${sdk_path}
                           export BUILD_PATH=\${sdk_path}/build
                           export OPTEE_BUILD_PATH=\${sdk_path}/build/optee
                           export PACK_PATH=\${sdk_path}/path
                           export OS_CODENAME=${os_codename}

                           sudo scripts/ansible/install-ansible.sh
                           sudo ansible-playbook scripts/ansible/oe-contributors-setup-cross-arm.yml
                           sudo apt install python3 python3-pyelftools p7zip-full -y

                           bash devex/cross-nuget/standalone-builds/linux/build-optee.sh
                           bash devex/cross-nuget/standalone-builds/linux/runner.sh
                           """

                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }
}

/* Builds OE for ARM64 inside a containar
 *
 * @param version           [string]  Version of Ubuntu to use
 * @param build_type        [string]  The build type to use.
 *                                    Choice of: Debug, Release, or RelWithDebInfo
 * @param pr_id             [string]  Optional - to checkout a specific oe pull request merge head
 */
def AArch64GNUTest(String version, String build_type, String pr_id = '') {
    stage("AArch64 GNU gcc Ubuntu${version} ${build_type}") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def runArgs = "--cap-add=SYS_PTRACE"
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

def checkDevFlows(String version, String compiler, String pr_id = '') {
    stage('Default compiler') {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-${version}"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def runArgs = "--cap-add=SYS_PTRACE"
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DHAS_QUOTE_PROVIDER=OFF -Wdev --warn-uninitialized -Werror=dev
                           ninja -v
                           """
                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", compiler, task, runArgs)
            }
        }
    }
}

def checkCI(String compiler, String pr_id = '') {
    stage('Check CI') {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx-20.04"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.oeCheckoutScm(pr_id)
                def runArgs = "--cap-add=SYS_PTRACE"
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
