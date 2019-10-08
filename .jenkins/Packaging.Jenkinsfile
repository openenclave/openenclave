@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240
CTEST_TIMEOUT_SECONDS = 480

def packageUpload(String version, String build_type) {
    stage("Ubuntu${version} SGX1FLC Package ${build_type}") {
        node("ACC-${version}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -DCMAKE_BUILD_TYPE=${build_type} -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave' -DCPACK_GENERATOR=DEB
                           make
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                           cpack
                           cpack -D CPACK_DEB_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
                           """
                oe.Run("clang-7", task)
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: "v0.7.x/${BUILD_NUMBER}/ubuntu/${version}/${build_type}/SGX1FLC/", containerName: 'oejenkins')
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: "v0.7.x/latest/ubuntu/${version}/${build_type}/SGX1FLC/", containerName: 'oejenkins')
            }
        }
    }
}

def WindowsUpload() {
    stage('Windows Release') {
        node('SGXFLC-Windows-DCAP') {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                dir('build') {
                    bat """
                        vcvars64.bat x64 && \
                        cmake.exe ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=RELEASE -DBUILD_ENCLAVES=ON -DUSE_LIBSGX=ON -DNUGET_PACKAGE_PATH=C:/openenclave/prereqs/nuget -DCPACK_GENERATOR=NuGet -Wdev && \
                        ninja.exe && \
                        ctest.exe -V -C RELEASE --timeout ${CTEST_TIMEOUT_SECONDS} && \
                        cpack && \
                        cpack -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
                        """
                }
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.nupkg', storageType: 'blobstorage', virtualPath: "v0.7.x/${BUILD_NUMBER}/windows/", containerName: 'oejenkins')
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.nupkg', storageType: 'blobstorage', virtualPath: "v0.7.x/latest/windows/", containerName: 'oejenkins')
            }
        }
    }
}

parallel "1604 SGX1FLC Package Debug" :          { packageUpload('1604', 'Debug') },
         "1604 SGX1FLC Package Release" :        { packageUpload('1604', 'Release') },
         "1604 SGX1FLC Package RelWithDebInfo" : { packageUpload('1604', 'RelWithDebInfo') },
         "1804 SGX1FLC Package Debug" :          { packageUpload('1804', 'Debug') },
         "1804 SGX1FLC Package Release" :        { packageUpload('1804', 'Release') },
         "1804 SGX1FLC Package RelWithDebInfo" : { packageUpload('1804', 'RelWithDebInfo') },
         "Windows Release" :                     { WindowsUpload() }
