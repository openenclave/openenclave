// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/************************************
* Shared Library for common functions
************************************/

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

def ContainerRun(String imageName, String compiler, String task, String runArgs="", registryUrl="https://openenclave.azurecr.io") {
    if (runArgs.contains("sgx_provision")) {
        def sgx_prv_gid = sh(script: "stat -c '%g' /dev/sgx_provision", returnStdout: true).trim()
        if (sgx_prv_gid && !runArgs.contains("--group-add")) {
            runArgs = "--group-add ${sgx_prv_gid} ${runArgs}"
        }
    }
    docker.withRegistry(registryUrl) {
        def image = docker.image(imageName)
        retry(3) {
            image.pull()
        }
        image.inside(runArgs) {
            dir("${WORKSPACE}/build") {
                Run(compiler, task)
            }
        }
    }
}

def runTask(String task) {
    dir("${WORKSPACE}/build") {
        sh """#!/usr/bin/env bash
                set -o errexit
                set -o pipefail
                source /etc/profile
                echo \$(whoami)
                ${task}
            """
    }
}

def Run(String compiler, String task) {
    def c_compiler
    def cpp_compiler

    compiler_components = compiler.split("-")
    if (compiler_components[0] == "clang" && compiler_components.size() > 1) {
        compiler = "clang"
        compiler_version = compiler_components[1]
    }

    switch(compiler) {
        case "cross":
            // In this case, the compiler is set by the CMake toolchain file. As
            // such, it is not necessary to specify anything in the environment.
            runTask(task)
            return
        case "clang":
            c_compiler = "clang"
            cpp_compiler = "clang++"
            break
        case "clang-7":
            c_compiler = "clang"
            cpp_compiler = "clang++"
            compiler_version = "7"
            break
        case "gcc":
            c_compiler = "gcc"
            cpp_compiler = "g++"
            break
        default:
            // This is needed for backwards compatibility with the old
            // implementation of the method.
            c_compiler = "clang"
            cpp_compiler = "clang++"
            compiler_version = "8"
    }
    if (compiler_version) {
        c_compiler += "-${compiler_version}"
        cpp_compiler += "-${compiler_version}"
    }
    withEnv(["CC=${c_compiler}","CXX=${cpp_compiler}"]) {
        withCredentials([
            string(credentialsId: 'thim-tdx-base-url', variable: 'AZDCAP_BASE_CERT_URL_TDX'),
            string(credentialsId: 'thim-tdx-region-url', variable: 'AZDCAP_REGION_URL')
        ]) {
            runTask(task)
        }
    }
}

def emailJobStatus(String status) {
    emailext (
      to: '$DEFAULT_RECIPIENTS',      
      subject: "[Jenkins Job ${status}] ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
      body: """            
            <p>               
            For additional logging details for this job please check: 
            <a href="${env.BUILD_URL}">${env.JOB_NAME} - ${env.BUILD_NUMBER}</a>
            </p>
            """,
      recipientProviders: [[$class: 'DevelopersRecipientProvider'], [$class: 'RequesterRecipientProvider']],
      mimeType: 'text/html'     
    )
}

/**
 * Installs Azure CLI on the current agent.
 * Supports Ubuntu (via apt) and Windows (via MSI).
 */
def installAzureCLI() {
    if (isUnix()) {
        retry(10) {
            sh """
                ${helpers.WaitForAptLock()}
                sudo apt-get update
                sudo apt-get -y install ca-certificates curl apt-transport-https lsb-release gnupg
                curl -sL https://packages.microsoft.com/keys/microsoft.asc |
                    gpg --dearmor |
                    sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null
                AZ_REPO=\$(lsb_release -cs)
                echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ \$AZ_REPO main" |
                    sudo tee /etc/apt/sources.list.d/azure-cli.list
                ${helpers.WaitForAptLock()}
                sudo apt-get update
                sudo apt-get -y install azure-cli jq
                az --version
                which az
            """
        }
    } else {
        def azPath = 'C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin'
        retry(10) {
            powershell '''
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri https://aka.ms/installazurecliwindowsx64 -OutFile .\\AzureCLI.msi
                $sig = Get-AuthenticodeSignature .\\AzureCLI.msi
                if ($sig.Status -ne 'Valid') {
                    throw "Azure CLI MSI signature validation failed: $($sig.Status)"
                }
                Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
                Remove-Item .\\AzureCLI.msi
            '''
        }
        if (!fileExists("${azPath}\\az.cmd")) {
            error "Azure CLI installation failed: az.cmd not found in ${azPath}"
        }
        if (!env.PATH.contains(azPath)) {
            env.PATH = "${azPath};${env.PATH}"
        }
        powershell '''
            az --version
            (Get-Command az).Source
        '''
    }
}

def exec_with_retry(int max_retries = 10, int retry_timeout = 30, Closure body) {
    int retry_count = 1
    while (retry_count <= max_retries) {
        try {
            body.call()
            break
        } catch (Exception e) {
            if (retry_count == max_retries) {
                throw e
            }
            println("Command failed. Retry count ${retry_count}/${max_retries}. Retrying in ${retry_timeout} seconds")
            sleep(retry_timeout)
            retry_count += 1
            continue
        }
    }
}
