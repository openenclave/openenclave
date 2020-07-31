// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

BRANCH_NAME = env.BRANCH_NAME ?: "master"
OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

GLOBAL_TIMEOUT_MINUTES = 240
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
                oe.Run("clang-7", task)
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: "${BRANCH_NAME}/${BUILD_NUMBER}/ubuntu/${version}/${build_type}/lvi-mitigation-${lvi_mitigation}/SGX1FLC/", containerName: 'oejenkins')
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: "${BRANCH_NAME}/latest/ubuntu/${version}/${build_type}/lvi-mitigation-${lvi_mitigation}/SGX1FLC/", containerName: 'oejenkins')
            }
        }
    }
}

def WindowsPackaging(String version, String build_type, String lvi_mitigation = 'None') {
    stage("Windows SGX1FLC ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node("SGXFLC-Windows-${version}-DCAP") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                oe.WinCompilePackageTest("build", build_type, "ON", CTEST_TIMEOUT_SECONDS, lvi_mitigation)
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.nupkg', storageType: 'blobstorage', virtualPath: "${BRANCH_NAME}/${BUILD_NUMBER}/windows/${version}/${build_type}/lvi-mitigation-${lvi_mitigation}/SGX1FLC/", containerName: 'oejenkins')
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.nupkg', storageType: 'blobstorage', virtualPath: "${BRANCH_NAME}/latest/windows/${version}/${build_type}/lvi-mitigation-${lvi_mitigation}/SGX1FLC/", containerName: 'oejenkins')
            }
        }
    }
}

try{
    oe.emailJobStatus('STARTED')
    parallel "1604 SGX1FLC Package Debug" :          { LinuxPackaging('1604', 'Debug') },
         "1604 SGX1FLC Package Debug LVI" :          { LinuxPackaging('1604', 'Debug', 'ControlFlow') },
         "1604 SGX1FLC Package Release" :            { LinuxPackaging('1604', 'Release') },
         "1604 SGX1FLC Package Release LVI" :        { LinuxPackaging('1604', 'Release', 'ControlFlow') },
         "1604 SGX1FLC Package RelWithDebInfo" :     { LinuxPackaging('1604', 'RelWithDebInfo') },
         "1604 SGX1FLC Package RelWithDebInfo LVI" : { LinuxPackaging('1604', 'RelWithDebInfo', 'ControlFlow') },
         "1804 SGX1FLC Package Debug" :              { LinuxPackaging('1804', 'Debug') },
         "1804 SGX1FLC Package Debug LVI" :          { LinuxPackaging('1804', 'Debug', 'ControlFlow') },
         "1804 SGX1FLC Package Release" :            { LinuxPackaging('1804', 'Release') },
         "1804 SGX1FLC Package Release LVI" :        { LinuxPackaging('1804', 'Release', 'ControlFlow') },
         "1804 SGX1FLC Package RelWithDebInfo" :     { LinuxPackaging('1804', 'RelWithDebInfo') },
         "1804 SGX1FLC Package RelWithDebInfo LVI" : { LinuxPackaging('1804', 'RelWithDebInfo', 'ControlFlow') },
         "Windows 2016 Debug" :                      { WindowsPackaging('2016','Debug') },
         "Windows 2016 Debug LVI" :                  { WindowsPackaging('2016','Debug', 'ControlFlow') },
         "Windows 2016 Release" :                    { WindowsPackaging('2016','Release') },
         "Windows 2016 Release LVI" :                { WindowsPackaging('2016','Release', 'ControlFlow') },
         "Windows 2019 Debug" :                      { WindowsPackaging('2019','Debug') },
         "Windows 2019 Debug LVI" :                  { WindowsPackaging('2019','Debug', 'ControlFlow') },
         "Windows 2019 Release" :                    { WindowsPackaging('2019','Release') },
         "Windows 2019 Release LVI" :                { WindowsPackaging('2019','Release', 'ControlFlow') }
} catch(Exception e) {
    println "Caught global pipeline exception :" + e
    GLOBAL_ERROR = e
    throw e
} finally {
    currentBuild.result = (GLOBAL_ERROR != null) ? 'FAILURE' : "SUCCESS"
    oe.emailJobStatus(currentBuild.result)
}
