// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*************************************
* Shared Library for OpenEnclave Tests
*************************************/

// Azure Linux

def ACCCodeCoverageTest(String label, String compiler, String build_type) {
    stage("${label} ${compiler} ${build_type} Code Coverage") {
        node("${label}") {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = helpers.CmakeArgs(build_type)
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ${helpers.TestCommand()}
                           ninja code_coverage
                           """
                common.Run(compiler, task)

                // Publish the report via Cobertura Plugin.
                cobertura coberturaReportFile: 'build/coverage/coverage.xml'

                // Publish the result to the PR(s) via GitHub Coverage reporter Plugin.
                // Workaround to obtain the PR id(s) as Bors does not us to grab them reliably.
                def log = sh (script: "git log -1 | grep -Po '(Try #\\K|Merge #\\K)[^:]*'", returnStdout: true).trim()
                def id_list = log.split(' #')
                id_list.each {
                    echo "PR ID: ${it}, REPOSITORY_NAME: ${REPOSITORY_NAME}"
                    withEnv(["CHANGE_URL=https://github.com/${REPOSITORY_NAME}/pull/${it}"]) {
                        publishCoverageGithub(filepath:'build/coverage/coverage.xml',
                                              coverageXmlType: 'cobertura',
                                              comparisonOption: [ value: 'optionFixedCoverage', fixedCoverage: '0.60' ],
                                              coverageRateType: 'Line')
                    }
                }
            }
        }
    }
}

def ACCTest(String label, String compiler, String build_type, List extra_cmake_args = [], List test_env = [], boolean fresh_install = false) {
    stage("${label} ${compiler} ${build_type}, extra_cmake_args: ${extra_cmake_args}, test_env: ${test_env}${fresh_install ? ", e2e" : ""}") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                if (fresh_install) {
                    sh  """
                        sudo bash scripts/ansible/install-ansible.sh
                        # Run ACC Playbook
                        for i in 1 2 3 4 5
                        do
                            sudo \$(which ansible-playbook) scripts/ansible/oe-contributors-acc-setup.yml && break
                            sleep 60
                        done
                        """
                }
                def cmakeArgs = helpers.CmakeArgs(build_type,"OFF","ON","-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin",extra_cmake_args.join(' '))
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ${helpers.TestCommand()}
                           """
                withEnv(test_env) {
                    common.Run(compiler, task)
                }
            }
        }
    }
}

def ACCUpgradeTest(String label, String compiler, String version, List extra_cmake_args = [], List test_env = []) {
    stage("${label} Container ${version} RelWithDebInfo, extra_cmake_args: ${extra_cmake_args}") {
        node("${label}") {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = helpers.CmakeArgs("RelWithDebInfo","OFF","ON","-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin",extra_cmake_args.join(' '))
                withEnv(test_env) {
                    common.Run(compiler, helpers.InstallReleaseCommand())
                    helpers.TestSamplesCommand()
                    common.Run(compiler, helpers.ninjaBuildCommand(cmakeArgs))
                    common.Run(compiler, helpers.InstallBuildCommand())
                    helpers.TestSamplesCommand()
                }
            }
        }
    }
}

def ACCContainerTest(String label, String version, List extra_cmake_args = []) {
    stage("${label} Container ${version} RelWithDebInfo, extra_cmake_args: ${extra_cmake_args}") {
        node("${label}") {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = helpers.CmakeArgs("RelWithDebInfo","OFF","ON","-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin",extra_cmake_args.join(' '))
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ${helpers.TestCommand()}
                           """
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", "clang-10", task, "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket")
            }
        }
    }
}

def ACCPackageTest(String label, String version, List extra_cmake_args = []) {
    stage("${label} PackageTest ${version} RelWithDebInfo, extra_cmake_args: ${extra_cmake_args}") {
        node("${label}") {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = helpers.CmakeArgs("RelWithDebInfo","OFF","ON","-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin",extra_cmake_args.join(' '))
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
                    "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket"
                )
            }
        }
    }
}

def ACCHostVerificationTest(String version, String build_type) {
    /* Compile tests in SGX machine.  This will generate the necessary certs for the
    * host_verify test.
    */
    stage("ACC-1804 Generate Quote") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-18.04"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = "-G Ninja -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
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
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", "clang-10", task, "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket")

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
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                def cmakeArgs = "-G Ninja -DBUILD_ENCLAVES=OFF -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
                def task = """
                           ${helpers.ninjaBuildCommand(cmakeArgs)}
                           ctest -R host_verify --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}
                           """
                // Note: Include the commands to build and run the quote verification test above
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", "clang-10", task, "--cap-add=SYS_PTRACE")
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

def ACCHostVerificationPackageTest(String version, String build_type) {
    /* Generate an SGX report and two SGX certificates for the host_verify sample.
    * Also generate and install the host_verify package. Then run the host_verify sample.
    */
    stage("ACC-1804 Generate Quote") {
        node(globalvars.AGENTS_LABELS["acc-ubuntu-18.04"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def cmakeArgs = "-G Ninja -DCMAKE_BUILD_TYPE=${build_type} -Wdev"
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
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", "clang-10", task, "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket")

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
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                cmakeArgs = "-G Ninja \
                             -DBUILD_ENCLAVES=OFF \
                             -DCMAKE_BUILD_TYPE=${build_type} \
                             -DCMAKE_INSTALL_PREFIX=/opt/openenclave \
                             -DCOMPONENT=OEHOSTVERIFY \
                             -Wdev"
                cmakeArgsHostVerify = "-G Ninja \
                                       -DBUILD_ENCLAVES=OFF \
                                       -DCMAKE_BUILD_TYPE=${build_type} \
                                       -Wdev"
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
                common.ContainerRun("oetools-${version}:${params.DOCKER_TAG}", "clang-10", task, "--cap-add=SYS_PTRACE")
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
                            xcopy /E C:\\oe\\open-enclave.OEHOSTVERIFY\\openenclave C:\\openenclave\\
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

def OEReleaseTest(String label, String release_version, String oe_package = "open-enclave", String source = "Azure", boolean lvi_mitigation = false) {
    stage("OE Release Test ${label}") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                helpers.releaseInstall(release_version, oe_package, source)
                helpers.TestSamplesCommand(lvi_mitigation, oe_package)
            }
        }
    }
}

def TestIntelRCs(String label, String release_version, String oe_package = "open-enclave", String source = "GitHub", boolean lvi_mitigation = false, String dcap_url, String psw_url, String install_flags = "") {
    stage("Test Intel Drivers RCs ${label}") {
        node(label) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                helpers.dependenciesInstall(dcap_url, psw_url, install_flags)
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

def windowsLinuxElfBuild(String label, String version, String compiler, String build_type, String lvi_mitigation = 'None', String lvi_mitigation_skip_tests = 'OFF', List extra_cmake_args = []) {
    stage("Ubuntu ${version} SGX1 ${compiler} ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
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
                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", compiler, task, "--cap-add=SYS_PTRACE")
                stash includes: 'build/tests/**', name: "linux-${label}-${compiler}-${build_type}-lvi_mitigation=${lvi_mitigation}-${version}-${BUILD_NUMBER}"
            }
        }
    }
    stage("Windows ${label} ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node(globalvars.AGENTS_LABELS[label]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux-${label}-${compiler}-${build_type}-lvi_mitigation=${lvi_mitigation}-${version}-${BUILD_NUMBER}"
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

def windowsCrossCompile(String label, String build_type, String lvi_mitigation = 'None', String OE_SIMULATION = "0", String lvi_mitigation_skip_tests = 'OFF', List extra_cmake_args = []) {
    def node_label = globalvars.AGENTS_LABELS["${label}-dcap"]

    stage("Windows ${label} ${build_type} with SGX LVI_MITIGATION=${lvi_mitigation}") {
        node(node_label) {
            withEnv(["OE_SIMULATION=${OE_SIMULATION}"]) {
                timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                    // OFF value of quote provider until https://github.com/openenclave/openenclave-ci/pull/29 is merged
                    common.WinCompilePackageTest("build/X64-${build_type}", build_type, 'OFF', globalvars.CTEST_TIMEOUT_SECONDS, lvi_mitigation, lvi_mitigation_skip_tests, extra_cmake_args)
                }
            }
        }
    }
}

def windowsCrossPlatform(String label) {
    def node_label = globalvars.AGENTS_LABELS[label]
    stage("Windows ${node_label} Cross Plaform Build") {
        node(node_label) {
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

def simulationContainerTest(String version, String build_type, List extra_cmake_args = []) {
    stage("Simulation Ubuntu ${version} clang-10 ${build_type}, extra_cmake_args: ${extra_cmake_args}") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
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
                    common.ContainerRun("oetools-${version}:${DOCKER_TAG}", "clang-10", task, "--cap-add=SYS_PTRACE")
                }
            }
        }
    }
}

def buildCrossPlatform(String version) {
    stage("Ubuntu ${version} OP-TEE Build") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
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

                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", "clang-10", task, "--cap-add=SYS_PTRACE")
            }
        }
    }
}

def AArch64GNUTest(String version, String build_type) {
    stage("AArch64 GNU gcc Ubuntu${version} ${build_type}") {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
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
                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", "cross", task, "--cap-add=SYS_PTRACE")
            }
        }
    }
}

def checkDevFlows(String version) {
    stage('Default compiler') {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DHAS_QUOTE_PROVIDER=OFF -Wdev --warn-uninitialized -Werror=dev
                           ninja -v
                           """
                common.ContainerRun("oetools-${version}:${DOCKER_TAG}", "clang-10", task, "--cap-add=SYS_PTRACE")
            }
        }
    }
}

def checkCI() {
    stage('Check CI') {
        node(globalvars.AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(globalvars.GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                // At the moment, the check-ci script assumes that it's executed from the
                // root source code directory.
                common.ContainerRun("oetools-18.04:${DOCKER_TAG}", "clang-10", "cd ${WORKSPACE} && ./scripts/check-ci", "--cap-add=SYS_PTRACE")
            }
        }
    }
}
