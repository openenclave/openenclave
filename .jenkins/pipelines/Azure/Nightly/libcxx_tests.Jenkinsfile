// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

CTEST_TIMEOUT_SECONDS = 480


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
        string(name: 'REPOSITORY_NAME',   defaultValue: 'openenclave/openenclave', description: 'GitHub repository to build.')
        string(name: 'BRANCH_NAME',       defaultValue: 'master',                  description: 'Git branch to build.')
        string(name: 'DOCKER_TAG',        defaultValue: 'latest',                  description: 'Tag used to pull oetools docker image.')
        string(name: 'OECI_LIB_VERSION',  defaultValue: 'master',                  description: 'Version of OE Libraries to use')
        string(name: 'UBUNTU_2004_LABEL', defaultValue: 'ACC-2004-DC2',            description: '[Optional] Agent label used for Ubuntu 20.04')
        string(name: 'UBUNTU_2204_LABEL', defaultValue: 'ACC-2204',                description: '[Optional] Agent label used for Ubuntu 22.04')
    }
    stages {
        stage('Run tests') {
            steps {
                script {
                    parallel([
                        "Libcxx ACC2004 clang-11 Debug" :          { ACCLibcxxTest(params.UBUNTU_2004_LABEL, 'clang-11', 'Debug') },
                        "Libcxx ACC2204 clang-11 Debug" :          { ACCLibcxxTest(params.UBUNTU_2204_LABEL, 'clang-11', 'Debug') },
                        "Libcxx ACC2004 clang-11 RelWithDebInfo" : { ACCLibcxxTest(params.UBUNTU_2004_LABEL, 'clang-11', 'RelWithDebInfo') },
                        "Libcxx ACC2204 clang-11 RelWithDebInfo" : { ACCLibcxxTest(params.UBUNTU_2204_LABEL, 'clang-11', 'RelWithDebInfo') }                   
                    ])
                }
            }
        }
    }
}
