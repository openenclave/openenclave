@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()
GLOBAL_TIMEOUT_MINUTES = 240
CTEST_TIMEOUT_SECONDS = 480

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
    podTemplate(label: "${env.BUILD_TAG}-${version}", nodeSelector: "agentpool=agents${version}",
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

// Build Job matrix for steps to be executed in parallel by looping through the lists below
def versions = ["xenial", "bionic"]
def compilers = ['gcc', 'clang-7']
def build_types = ['Release', 'Debug', 'RelWithDebInfo']

def stepsForParallel = versions.collectEntries { version ->
    compilers.collectEntries {  compiler ->
        build_types.collectEntries { build_type ->
            ["${version} ${compiler} ${build_type}": { ubuntuTemplate(version) { accK8sTest(version, compiler, build_type) } } ]
        }

    }
}

parallel stepsForParallel

/*
parallel "Bionic gcc Debug": { ubuntuTemplate('bionic') { accK8sTest('bionic', 'gcc', 'Debug') } },
         "Xenial gcc Debug": { ubuntuTemplate('xenial') { accK8sTest('xenial', 'gcc', 'Debug') } },
         "Bionic gcc Release": { ubuntuTemplate('bionic') { accK8sTest('bionic', 'gcc', 'Release') } },
         "Xenial gcc Release": { ubuntuTemplate('xenial') { accK8sTest('xenial', 'gcc', 'Release') } },
         "Bionic gcc RelWithDebInfo": { ubuntuTemplate('bionic') { accK8sTest('bionic', 'gcc', 'RelWithDebInfo') } },
         "Xenial gcc RelWithDebInfo": { ubuntuTemplate('xenial') { accK8sTest('xenial', 'gcc', 'RelWithDebInfo') } },
         "Bionic clang-7 Debug": { ubuntuTemplate('bionic') { accK8sTest('bionic', 'clang-7', 'Debug') } },
         "Xenial clang-7 Debug": { ubuntuTemplate('xenial') { accK8sTest('xenial', 'clang-7', 'Debug') } },
         "Bionic clang-7 Release": { ubuntuTemplate('bionic') { accK8sTest('bionic', 'clang-7', 'Release') } },
         "Xenial clang-7 Release": { ubuntuTemplate('xenial') { accK8sTest('xenial', 'clang-7', 'Release') } },
         "Bionic clang-7 RelWithDebInfo": { ubuntuTemplate('bionic') { accK8sTest('bionic', 'clang-7', 'RelWithDebInfo') } },
         "Xenial clang-7 RelWithDebInfo": { ubuntuTemplate('xenial') { accK8sTest('xenial', 'clang-7', 'RelWithDebInfo') } }
*/
