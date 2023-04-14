// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

GLOBAL_TIMEOUT_MINUTES = 120
CTEST_TIMEOUT_SECONDS = 480
GLOBAL_ERROR = null




pipeline {
    agent any
    options {
        timeout(time: 240, unit: 'MINUTES')
        buildDiscarder(logRotator(artifactDaysToKeepStr: '90', artifactNumToKeepStr: '180', daysToKeepStr: '90', numToKeepStr: '180'))
    }
    parameters {
        string(name: 'REPOSITORY_NAME',       defaultValue: 'openenclave/openenclave',  description: 'GitHub repository to build.')
        string(name: 'BRANCH_NAME',           defaultValue: 'master',                   description: 'Git branch to build.')
        string(name: 'OECI_LIB_VERSION',      defaultValue: 'master',                   description: 'Version of OE Libraries to use')
        string(name: 'UBUNTU_2004_LABEL',     defaultValue: 'ACC-2004',                 description: '[Optional] Jenkins agent label to use for Ubuntu 20.04')
        string(name: 'WS2019_DCAP_CFL_LABEL', defaultValue: 'SGXFLC-Windows-2019-DCAP', description: '[Optional] Jenkins agent label to use for Windows Server 2019 with DCAP on Intel Coffee Lake')
        choice(name: 'COMPILER',              choices: ['clang-11', 'clang-10'],        description: 'Select a version of Clang for the build')
    }
    stages {
        stage('Run tests') {
            steps {
                script {
                    parallel([
                        "Ubuntu 20.04 SGX1FLC Package Debug LVI":          { tests.LinuxPackaging(params.UBUNTU_2004_LABEL, params.COMPILER, 'Debug', 'ControlFlow') },
                        "Ubuntu 20.04 SGX1FLC Package RelWithDebInfo LVI": { tests.LinuxPackaging(params.UBUNTU_2004_LABEL, params.COMPILER, 'RelWithDebInfo', 'ControlFlow') },
                        "Windows 2019 Debug LVI":                  { tests.WindowsPackaging(params.WS2019_DCAP_CFL_LABEL, params.COMPILER, 'Debug', 'ControlFlow') },
                        "Windows 2019 RelWithDebInfo":             { tests.WindowsPackaging(params.WS2019_DCAP_CFL_LABEL, params.COMPILER, 'RelWithDebInfo') },
                        "Windows 2019 RelWithDebInfo LVI":         { tests.WindowsPackaging(params.WS2019_DCAP_CFL_LABEL, params.COMPILER, 'RelWithDebInfo', 'ControlFlow') },
                        "Windows 2019 Sim Debug LVI":              { tests.WindowsPackaging(params.WS2019_DCAP_CFL_LABEL, params.COMPILER, 'Debug', 'ControlFlow', '1') },
                        "Windows 2019 Sim RelWithDebInfo":         { tests.WindowsPackaging(params.WS2019_DCAP_CFL_LABEL, params.COMPILER, 'RelWithDebInfo', 'None', '1') },
                        "Windows 2019 Sim RelWithDebInfo LVI":     { tests.WindowsPackaging(params.WS2019_DCAP_CFL_LABEL, params.COMPILER, 'RelWithDebInfo', 'ControlFlow', '1') }
                    ]) 
                }
            }
        }
    }
}
