#!/usr/bin/groovy
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package jenkins.common;

String dockerBuildArgs(String... args) {
    String argumentString = ""
    for(arg in args) {
        argumentString += " --build-arg ${arg}"
    }
    return argumentString
}

String dockerImage(String tag, String dockerfile = ".jenkins/Dockerfile", String buildArgs = "") {
    checkout scm
    return docker.build(tag, "${buildArgs} -f ${dockerfile} .")
}

def oetoolsImage(String version, String compiler, String task, String runArgs="") {
    String buildArgs = dockerBuildArgs("ubuntu_version=${version}")
    dockerImage("oetools:${version}", ".jenkins/Dockerfile", buildArgs).inside(runArgs) {
        dir("${WORKSPACE}/build") {
            Run(compiler, task)
        }
    }
}

def azureEnvironment(String task) {
    node("nonSGX") {
        String buildArgs = dockerBuildArgs("UID=\$(id -u)",
                                           "GID=\$(id -g)",
                                           "UNAME=\$(id -un)",
                                           "GNAME=\$(id -gn)")

        dockerImage("oetools-deploy", ".jenkins/Dockerfile.deploy", buildArgs).inside {
            timeout(60) {
                withCredentials([usernamePassword(credentialsId: 'SERVICE_PRINCIPAL_OSTCLAB',
                                                  passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                                  usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                                 string(credentialsId: 'OSCTLabSubID', variable: 'SUBSCRIPTION_ID'),
                                 string(credentialsId: 'TenantID', variable: 'TENANT_ID')]) {
                    dir('.jenkins/provision') {
                        sh "${task}"
                    }
                }
            }
        }
    }
}

def Run(String compiler, String task, Integer timeoutMinutes = 30) {
    def c_compiler = "clang-7"
    def cpp_compiler = "clang++-7"
    if (compiler == "gcc") {
        c_compiler = "gcc"
        cpp_compiler = "g++"
    }
    cleanWs()
    checkout scm

    withEnv(["CC=${c_compiler}","CXX=${cpp_compiler}"]) {
        timeout(timeoutMinutes) {
            dir("${WORKSPACE}/build") {
                sh "${task}"
            }
        }
    }
}

def deleteRG(List resourceGroups) {
    stage("Delete ${resourceGroups.toString()} resource groups") {
        resourceGroups.each { rg ->
            withEnv(["RESOURCE_GROUP=${rg}"]) {
                azureEnvironment("./cleanup.sh")
            }
        }
    }
}

return this
