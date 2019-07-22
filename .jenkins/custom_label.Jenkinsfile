@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

// The below timeout is set in minutes
GLOBAL_TIMEOUT = 240
// ctest timeout is set in seconds
CTEST_TIMEOUT = 480

def ACCTest(String label, String compiler, String build_type) {
    stage("${label} ${compiler} SGX1FLC ${build_type}") {
        node("${label}") {
            timeout(GLOBAL_TIMEOUT) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${build_type} -Wdev
                           ninja -v
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT}
                           """
                oe.Run(compiler, task)
            }
        }
    }
}

def ACCContainerTest(String label, String version) {
    stage("${label} Container RelWithDebInfo") {
        node("${label}") {
            timeout(GLOBAL_TIMEOUT) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -Wdev
                           ninja -v
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT}
                           """
                oe.ContainerRun("oetools-full-${version}", "clang-7", task, "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx")
            }
        }
    }
}

def win2016CrossCompile(String build_type, String use_libsgx = 'OFF') {
    stage("Windows ${build_type} with SGX ${use_libsgx}") {
        node(WINDOWS_2016_CUSTOM_LABEL) {
            timeout(GLOBAL_TIMEOUT) {
                cleanWs()
                checkout scm
                dir("build/X64-${build_type}") {

                  /* We need to copy nuget into the expected location
                  https://github.com/microsoft/openenclave/blob/a982b46cf440def8fb66e94f2622a4f81e2b350b/host/CMakeLists.txt#L188-L197 */
                  powershell 'Copy-Item -Recurse C:\\openenclave\\prereqs\\nuget ${env:WORKSPACE}\\prereqs'

                  bat """
                      vcvars64.bat x64 && \
                      cmake.exe ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${build_type} -DBUILD_ENCLAVES=ON -DUSE_LIBSGX=${use_libsgx} -Wdev && \
                      ninja.exe && \
                      ctest.exe -V -C ${build_type} --timeout ${CTEST_TIMEOUT}
                      """
                }
            }
        }
    }
}


properties([buildDiscarder(logRotator(artifactDaysToKeepStr: '90',
                                      artifactNumToKeepStr: '180',
                                      daysToKeepStr: '90',
                                      numToKeepStr: '180')),
            [$class: 'JobRestrictionProperty']])

parallel "ACC1604 clang-7 RelWithDebInfo" :                     { ACCTest(UBUNTU_1604_CUSTOM_LABEL, 'clang-7', 'RelWithDebInfo') },
         "ACC1604 gcc RelWithDebInfo" :                         { ACCTest(UBUNTU_1604_CUSTOM_LABEL, 'gcc', 'RelWithDebInfo') },
         "ACC1604 Container RelWithDebInfo" :                   { ACCContainerTest(UBUNTU_1604_CUSTOM_LABEL, '16.04') },
         "ACC1804 clang-7 RelWithDebInfo" :                     { ACCTest(UBUNTU_1804_CUSTOM_LABEL, 'clang-7', 'RelWithDebInfo') },
         "ACC1804 gcc RelWithDebInfo" :                         { ACCTest(UBUNTU_1804_CUSTOM_LABEL, 'gcc', 'RelWithDebInfo') },
         "ACC1804 Container RelWithDebInfo" :                   { ACCContainerTest(UBUNTU_1804_CUSTOM_LABEL, '18.04') }
