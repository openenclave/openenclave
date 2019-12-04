@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()
GLOBAL_TIMEOUT_MINUTES = 240
CTEST_TIMEOUT_SECONDS = 480

// Create Kubernetes Pod Template
def ubuntuTemplate(String version, Closure body) {
    if (version == "xenial") {
        image_name = 'oeciteam/oetools-full-16.04'
    } else if (version == "bionic"){
        image_name = 'oeciteam/oetools-full-18.04'
    } else {
        println("Supported Ubuntu versions are: xenial and bionic")
        currentBuild.result = 'FAILED'
        return
    }
    podTemplate(label: "${env.BUILD_TAG}-${version}",
                nodeSelector: "agentpool=agents${version}",
                containers: [
                  containerTemplate(name: "oetools-${version}",
                                    image: image_name,
                                    ttyEnabled: true,
                                    privileged: true)
                ],
                volumes: [
                  hostPathVolume(mountPath: '/dev/sgx', hostPath: '/dev/sgx')
                ]) {
                  body()
                }
}


def nonSGXUbuntuTemplate(String version, Closure body) {
    if (version == "xenial") {
        image_name = 'oeciteam/oetools-full-16.04'
    } else if (version == "bionic") {
        image_name = 'oeciteam/oetools-full-18.04'
    } else if (version == "minimal") {
        image_name = 'oeciteam/oetools-minimal-18.04'
    } else {
        println("Supported Ubuntu versions are: xenial,bionic and minimal")
        currentBuild.result = 'FAILED'
        return
    }
    podTemplate(label: "${env.BUILD_TAG}-${version}",
                nodeSelector: "agentpool=agents${version}",
                containers: [
                  containerTemplate(name: "oetools-${version}",
                                    image: image_name,
                                    ttyEnabled: true)
                ]) {
                  body()
                }
}


def accK8sTest(String version, String compiler, String build_type) {
    node("${env.BUILD_TAG}-${version}") {
        container("oetools-${version}") {
            stage("Build Openenclave ${build_type} with ${compiler} on oetools-${version}") {
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


def simulationTest(String version, String platform_mode, String build_type) {
    def has_quote_provider = "OFF"
    if (platform_mode == "SGX1FLC") {
        has_quote_provider = "ON"
    }
    stage("Sim clang-7 Ubuntu${version} ${platform_mode} ${build_type}") {
        node("${env.BUILD_TAG}-${version}") {
            container("oetools-${version}") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    checkout scm
                    withEnv(["OE_SIMULATION=1"]) {
                        def task = """
                                   cmake ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${build_type} -DHAS_QUOTE_PROVIDER=${has_quote_provider} -Wdev
                                   ninja -v
                                   ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                                   """
                        oe.Run("clang-7", task)
                    }
                }
            }
        }
    }
}


def ACCPackageTest String version) {
    stage("ACC-${version} Container RelWithDebInfo") {
        node("${env.BUILD_TAG}-${version}") {
            container("oetools-${version}") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    cleanWs()
                    checkout scm
                    def task = """
                               cmake ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -Wdev -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave' -DCPACK_GENERATOR=DEB
                               ninja -v
                               ninja -v package
                               sudo ninja -v install
                               cp -r /opt/openenclave/share/openenclave/samples ~/
                               cd ~/samples
                               source /opt/openenclave/share/openenclave/openenclaverc
                               for i in *; do
                                   if [ -d \${i} ]; then
                                       cd \${i}
                                       mkdir build
                                       cd build
                                       cmake ..
                                       make
                                       make run
                                       cd ../..
                                   fi
                               done
                               """
                    oe.Run("clang-7", task)
            }
        }
    }
}


def AArch64GNUTest(String version, String build_type) {
    stage("AArch64 GNU gcc Ubuntu${version} ${build_type}") {
        node("${env.BUILD_TAG}-${version}") {
            container("oetools-${version}") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
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
                    oe.Run("cross", task)
                }
            }
        }
    }
}


def checkDevFlows(String version) {
    stage('Default compiler') {
      node("${env.BUILD_TAG}-${version}") {
          container("oetools-${version}") {
              timeout(GLOBAL_TIMEOUT_MINUTES) {
                  cleanWs()
                  checkout scm
                  def task = """
                             cmake ${WORKSPACE} -G Ninja -DHAS_QUOTE_PROVIDER=OFF -Wdev --warn-uninitialized -Werror=dev
                             ninja -v
                             """
                  oe.Run("clang-7", task)
              }
          }
        }
    }
}

def checkCI() {
    stage('Check CI') {
        node("${env.BUILD_TAG}-minimal") {
            container("oetools-minimal") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    cleanWs()
                    checkout scm
                    // At the moment, the check-ci script assumes that it's executed from the
                    // root source code directory.
                    oe.Run("clang-7", "cd ${WORKSPACE} && ./scripts/check-ci")
                }
            }
        }
    }
}

// Build Job matrix for steps to be executed in parallel by looping through the lists below
def versions = ["bionic", "xenial"]
def compilers = ['gcc', 'clang-7']
def build_types = ['Release', 'Debug', 'RelWithDebInfo']
def platform_modes = ['SGX1', 'SGX1FLC']

def stepsForParallel = [:]

versions.each { version ->
    build_types.each { build_type ->
        compilers.each { compiler ->
            stepsForParallel["Container ${version} ${compiler} ${build_type}"] = { ubuntuTemplate(version) { accK8sTest(version, compiler, build_type) } }
        }
        platform_modes.each { platform_mode ->
            stepsForParallel["Simulation ${version} clang-7 ${build_type}"] = { nonSGXUbuntuTemplate(version) { simulationTest(version, platform_mode, build_type) } }
        }
        stepsForParallel["AArch64 ${version} GNU gcc ${build_type}"] = { nonSGXUbuntuTemplate(version) { AArch64GNUTest(version, build_type) } }
    }
    stepsForParallel["ACC-${version} Package RelWithDebInfo"] = { ubuntuTemplate(version) { ACCPackageTest(version) } }
    stepsForParallel["Check Developer Experience Ubuntu ${version}"] = { nonSGXUbuntuTemplate(version) { checkDevFlows(version) } }
}

nonSGXUbuntuTemplate('minimal') { checkCI() }
parallel stepsForParallel
