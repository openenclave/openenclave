// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

CTEST_TIMEOUT_SECONDS = 480
FOCAL_LABEL = "ACC-2004-DC2"
BIONIC_LABEL = "ACC-1804-DC2"


def ACCLibcxxTest(String label, String compiler, String build_type) {
    stage("${label} SGX1FLC ${compiler} ${build_type}") {
        node(label) {
            timeout(time: 300, unit: 'MINUTES') {
                cleanWs()
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: "${params.BRANCH_NAME}"]],
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [[
                        $class: 'PruneStaleBranch',
                        $class: 'SubmoduleOption',
                        disableSubmodules: false,
                        recursiveSubmodules: true,
                        trackingSubmodules: false
                    ]], 
                    submoduleCfg: [],
                    userRemoteConfigs: [[
                        url: "https://github.com/${params.REPOSITORY_NAME}.git",
                        credentialsId: 'github-oeciteam-user-pat'
                    ]]
                ])
                def task = """
                           cmake .. -DCMAKE_BUILD_TYPE=${build_type} -DHAS_QUOTE_PROVIDER=ON -DENABLE_FULL_LIBCXX_TESTS=ON
                           make
                           ctest -VV -debug --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                common.Run(compiler, task)
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
        string(name: 'DOCKER_TAG',       defaultValue: 'latest',                  description: 'Tag used to pull oetools docker image.')
        string(name: 'OECI_LIB_VERSION', defaultValue: 'master',                  description: 'Version of OE Libraries to use')
    }
    stages {
        stage('Run tests') {
            steps {
                script {
                    parallel([
                        "Libcxx ACC2004 clang-10 Debug" :          { ACCLibcxxTest(FOCAL_LABEL,  'clang-10', 'Debug') },
                        "Libcxx ACC2004 clang-10 RelWithDebInfo" : { ACCLibcxxTest(FOCAL_LABEL,  'clang-10', 'RelWithDebInfo') },
                        "Libcxx ACC1804 clang-10 Debug" :          { ACCLibcxxTest(BIONIC_LABEL, 'clang-10', 'Debug') },
                        "Libcxx ACC1804 clang-10 RelWithDebInfo" : { ACCLibcxxTest(BIONIC_LABEL, 'clang-10', 'RelWithDebInfo') }
                    ])
                }
            }
        }
    }
}
