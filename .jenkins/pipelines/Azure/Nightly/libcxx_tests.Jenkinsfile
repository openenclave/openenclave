// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

GLOBAL_TIMEOUT_MINUTES = 240
CTEST_TIMEOUT_SECONDS = 480
GLOBAL_ERROR = null
BIONIC_LABEL = "Libcxx-Nightly-Ubuntu-1804"


def ACCLibcxxTest(String label, String compiler, String build_type) {
    stage("${label} SGX1FLC ${compiler} ${build_type}") {
        node(label) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake .. -DCMAKE_BUILD_TYPE=${build_type} -DHAS_QUOTE_PROVIDER=ON -DENABLE_FULL_LIBCXX_TESTS=ON
                           make
                           ctest -VV -debug --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                oe.Run(compiler, task)
            }
        }
    }
}


try {
    oe.emailJobStatus('STARTED')
    parallel "Libcxx ACC1804 clang-8 Debug" :          { ACCLibcxxTest(BIONIC_LABEL, 'clang-8', 'Debug') },
             "Libcxx ACC1804 clang-8 Release" :        { ACCLibcxxTest(BIONIC_LABEL, 'clang-8', 'Release') },
             "Libcxx ACC1804 clang-8 RelWithDebInfo" : { ACCLibcxxTest(BIONIC_LABEL, 'clang-8', 'RelWithDebInfo') },
} catch(Exception e) {
    println "Caught global pipeline exception :" + e
    GLOBAL_ERROR = e
    throw e
} finally {
    currentBuild.result = (GLOBAL_ERROR != null) ? 'FAILURE' : "SUCCESS"
    oe.emailJobStatus(currentBuild.result)
}
