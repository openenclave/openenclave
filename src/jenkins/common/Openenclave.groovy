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
    return docker.build(tag, "${buildArgs} -f ${dockerfile} .")
}

def ContainerRun(String imageName, String compiler, String task, String runArgs="") {
    docker.withRegistry("https://oejenkinscidockerregistry.azurecr.io", "oejenkinscidockerregistry") {
        def image = docker.image("${imageName}:latest")
        image.pull()
        image.inside(runArgs) {
            dir("${WORKSPACE}/build") {
                Run(compiler, task)
            }
        }
    }
}

def azureEnvironment(String task) {
    timeout(60) {
        withCredentials([usernamePassword(credentialsId: 'SERVICE_PRINCIPAL_OSTCLAB',
                                          passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                          usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                         string(credentialsId: 'OSCTLabSubID', variable: 'SUBSCRIPTION_ID'),
                         string(credentialsId: 'TenantID', variable: 'TENANT_ID')]) {
            docker.withRegistry("https://oejenkinscidockerregistry.azurecr.io", "oejenkinscidockerregistry") {
                def image = docker.image("oetools-deploy:latest")
                image.pull()
                image.inside {
                    sh """#!/usr/bin/env bash
                          set -o errexit
                          set -o pipefail
                          source /etc/profile
                          ${task}
                       """
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

    withEnv(["CC=${c_compiler}","CXX=${cpp_compiler}"]) {
        timeout(timeoutMinutes) {
            dir("${WORKSPACE}/build") {
                sh """#!/usr/bin/env bash
                      set -o errexit
                      set -o pipefail
                      source /etc/profile
                      ${task}
                   """
            }
        }
    }
}

def deleteRG(List resourceGroups) {
    stage("Delete ${resourceGroups.toString()} resource groups") {
        resourceGroups.each { rg ->
            withEnv(["RESOURCE_GROUP=${rg}"]) {
                dir("${WORKSPACE}/.jenkins/provision") {
                    azureEnvironment("./cleanup.sh")
                }
            }
        }
    }
}

return this
