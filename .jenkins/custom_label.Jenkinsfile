@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240
CTEST_TIMEOUT_SECONDS = 480

def ACCTest(String label, String compiler, String build_type) {
    stage("${label} ${compiler} SGX1FLC ${build_type}") {
        node("${label}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${build_type} -Wdev
                           ninja -v
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                oe.Run(compiler, task)
            }
        }
    }
}

def ACCContainerTest(String label, String version) {
    stage("${label} Container RelWithDebInfo") {
        node("${label}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -Wdev
                           ninja -v
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", "clang-7", task, "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx")
            }
        }
    }
}

def win2016CrossCompile(String build_type, String use_libsgx = 'OFF') {
    stage("Windows ${build_type} with SGX ${use_libsgx}") {
        node(WINDOWS_2016_CUSTOM_LABEL) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
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
                      ctest.exe -V -C ${build_type} --timeout ${CTEST_TIMEOUT_SECONDS}
                      """
                }
            }
        }
    }
}

def win2016LinuxElfBuild(String version, String compiler, String build_type) {
    def ubuntu_label = UBUNTU_1604_CUSTOM_LABEL
    if ( version == "18.04" ) {
      ubuntu_label = UBUNTU_1804_CUSTOM_LABEL
    }
    stage("Ubuntu ${version} SGX1 ${compiler} ${build_type}}") {
        node(ubuntu_label) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${build_type} -DUSE_LIBSGX=ON -Wdev
                           ninja -v
                           """
                oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", compiler, task, "--cap-add=SYS_PTRACE")
                stash includes: 'build/tests/**', name: "linux-${compiler}-${build_type}-${version}-${BUILD_NUMBER}"
            }
        }
    }
    stage("Windows ${build_type}") {
        node(WINDOWS_2016_CUSTOM_LABEL) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux-${compiler}-${build_type}-${version}-${BUILD_NUMBER}"
                bat 'move build linuxbin'
                powershell 'Copy-Item -Recurse C:\\openenclave\\prereqs\\nuget ${env:WORKSPACE}\\prereqs'
                dir('build') {
                  bat """
                      vcvars64.bat x64 && \
                      cmake.exe ${WORKSPACE} -G Ninja -DADD_WINDOWS_ENCLAVE_TESTS=ON -DBUILD_ENCLAVES=OFF -DUSE_LIBSGX=ON -DCMAKE_BUILD_TYPE=${build_type} -DLINUX_BIN_DIR=${WORKSPACE}\\linuxbin\\tests -Wdev && \
                      ninja -v && \
                      ctest.exe -V -C ${build_type} --timeout ${CTEST_TIMEOUT_SECONDS}
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
         "ACC1804 Container RelWithDebInfo" :                   { ACCContainerTest(UBUNTU_1804_CUSTOM_LABEL, '18.04') },
         "Win2016 Ubuntu1604 clang-7 Debug Linux-Elf-build" :   { win2016LinuxElfBuild('16.04', 'clang-7', 'Debug') },
         "Win2016 Ubuntu1804 clang-7 Release Linux-Elf-build" : { win2016LinuxElfBuild('18.04', 'clang-7', 'Release') },
         "Win2016 Ubuntu1804 gcc Debug Linux-Elf-build" :       { win2016LinuxElfBuild('18.04', 'gcc', 'Debug') },
         "Win2016 Debug Cross Compile" :                        { win2016CrossCompile('Debug') }
