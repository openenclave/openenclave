// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240
CTEST_TIMEOUT_SECONDS = 480
GLOBAL_ERROR = null

def ACClibcxxTest(String label, String compiler, String build_type) {
    stage("${label} SGX1FLC ${compiler} ${build_type}") {
        node("${label}") {
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

    parallel "libcxx ACC1604 clang-7 Debug" :          { ACClibcxxTest("LIBCXX-1604", 'clang-7', 'Debug') },
             "libcxx ACC1604 clang-7 Release" :        { ACClibcxxTest("LIBCXX-1604", 'clang-7','Release') },
             "libcxx ACC1604 clang-7 RelWithDebInfo" : { ACClibcxxTest("LIBCXX-1604", 'clang-7', 'RelWithDebinfo') },
             "libcxx ACC1604 gcc Debug" :              { ACClibcxxTest("LIBCXX-1604", 'gcc', 'Debug') },
             "libcxx ACC1604 gcc Release" :            { ACClibcxxTest("LIBCXX-1604", 'gcc', 'Release') },
             "libcxx ACC1604 gcc RelWithDebInfo" :     { ACClibcxxTest("LIBCXX-1604", 'gcc', 'RelWithDebInfo') },
             "libcxx ACC1804 clang-7 Debug" :          { ACClibcxxTest("LIBCXX-1804", 'clang-7', 'Debug') },
             "libcxx ACC1804 clang-7 Release" :        { ACClibcxxTest("LIBCXX-1804", 'clang-7', 'Release') },
             "libcxx ACC1804 clang-7 RelWithDebInfo" : { ACClibcxxTest("LIBCXX-1804", 'clang-7', 'RelWithDebinfo') },
             "libcxx ACC1804 gcc Debug" :              { ACClibcxxTest("LIBCXX-1804", 'gcc', 'Debug') },
             "libcxx ACC1804 gcc Release" :            { ACClibcxxTest("LIBCXX-1804", 'gcc', 'Release') },
             "libcxx ACC1804 gcc RelWithDebInfo" :     { ACClibcxxTest("LIBCXX-1804", 'gcc', 'RelWithDebinfo') }
} catch(Exception e) {
    println "Caught global pipeline exception :" + e
    GLOBAL_ERROR = e
    throw e   
} finally {

    currentBuild.result = (GLOBAL_ERROR != null) ? 'FAILURE' : "SUCCESS"    
    oe.emailJobStatus(currentBuild.result)
}
