// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

GLOBAL_TIMEOUT_MINUTES = 120
CTEST_TIMEOUT_SECONDS = 480
GLOBAL_ERROR = null

def LinuxPackaging(String version, String build_type, String lvi_mitigation = 'None') {
    stage("Ubuntu${version} SGX1FLC Package ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node("ACC-${version}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
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
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                common.Run("clang-10", task)
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: "${BRANCH_NAME}/${BUILD_NUMBER}/ubuntu/${version}/${build_type}/lvi-mitigation-${lvi_mitigation}/SGX1FLC/", containerName: 'oejenkins')
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: "${BRANCH_NAME}/latest/ubuntu/${version}/${build_type}/lvi-mitigation-${lvi_mitigation}/SGX1FLC/", containerName: 'oejenkins')
            }
        }
    }
}

def WindowsPackaging(String version, String build_type, String lvi_mitigation = 'None', String simulation = '1') {
    stage("Windows SGX1FLC ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node("SGXFLC-Windows-${version}-DCAP") {
            withEnv(["OE_SIMULATION=${simulation}"]) {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    common.WinCompilePackageTest("build", build_type, "ON", CTEST_TIMEOUT_SECONDS, lvi_mitigation)
                    azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.nupkg', storageType: 'blobstorage', virtualPath: "${BRANCH_NAME}/${BUILD_NUMBER}/windows/${version}/${build_type}/lvi-mitigation-${lvi_mitigation}/SGX1FLC/", containerName: 'oejenkins')
                    azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.nupkg', storageType: 'blobstorage', virtualPath: "${BRANCH_NAME}/latest/windows/${version}/${build_type}/lvi-mitigation-${lvi_mitigation}/SGX1FLC/", containerName: 'oejenkins')
                }
            }
        }
    }
}

pipeline {
    agent any
    options {
        timeout(time: 240, unit: 'MINUTES')
        buildDiscarder(logRotator(artifactDaysToKeepStr: '90', artifactNumToKeepStr: '180', daysToKeepStr: '90', numToKeepStr: '180'))
    }
    parameters {
        string(name: 'REPOSITORY_NAME',  defaultValue: 'openenclave/openenclave', description: 'GitHub repository to build.')
        string(name: 'BRANCH_NAME',      defaultValue: 'master',                  description: 'Git branch to build.')
        string(name: 'OECI_LIB_VERSION', defaultValue: 'master',                  description: 'Version of OE Libraries to use')
    }
    stages {
        stage('Run tests') {
            steps {
                script {
                    parallel([
                        "2004 SGX1FLC Package Debug LVI":          { LinuxPackaging('2004', 'Debug', 'ControlFlow') },
                        "2004 SGX1FLC Package RelWithDebInfo LVI": { LinuxPackaging('2004', 'RelWithDebInfo', 'ControlFlow') },
                        "1804 SGX1FLC Package Debug LVI":          { LinuxPackaging('1804', 'Debug', 'ControlFlow') },
                        "1804 SGX1FLC Package RelWithDebInfo LVI": { LinuxPackaging('1804', 'RelWithDebInfo', 'ControlFlow') },
                        "Windows 2019 Debug LVI":                  { WindowsPackaging('2019','Debug', 'ControlFlow') },
                        "Windows 2019 RelWithDebInfo":             { WindowsPackaging('2019','RelWithDebInfo') },
                        "Windows 2019 RelWithDebInfo LVI":         { WindowsPackaging('2019','RelWithDebInfo', 'ControlFlow') },
                        "Windows 2019 Sim Debug LVI":              { WindowsPackaging('2019','Debug', 'ControlFlow', '1') },
                        "Windows 2019 Sim RelWithDebInfo":         { WindowsPackaging('2019','RelWithDebInfo', 'None', '1') },
                        "Windows 2019 Sim RelWithDebInfo LVI":     { WindowsPackaging('2019','RelWithDebInfo', 'ControlFlow', '1') }
                    ]) 
                }
            }
        }
    }
}
