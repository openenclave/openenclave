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

def ContainerRun(String imageName, String compiler, String task, String runArgs="", registryUrl="https://oejenkinscidockerregistry.azurecr.io", registryName="oejenkinscidockerregistry") {
    exec_with_retry(10,300){
        docker.withRegistry(registryUrl, registryName) {
            def image = docker.image(imageName)
            image.pull()
            image.inside(runArgs) {
                dir("${WORKSPACE}/build") {
                    Run(compiler, task)
                }
            }
        }
    }
}

/**
 * Runs tasks within a Docker container
 *
 * @param imageName     The name of the Docker image to run.
 * @param compiler      The compiler to use, if applicable.
 * @param tasks         List of tasks to run within the Docker container. Must be in Jenkins groovy syntax.
 * @param runArgs       [Optional] Arguments to pass when calling Docker run
 * @param registryUrl   [Optional] Url of the Docker registry to pull from. Defaults to "https://oejenkinscidockerregistry.azurecr.io"
 * @param registryName  [Optional] Name of the Docker registry to pull from. Defaults to "oejenkinscidockerregistry"
 */
def ContainerTasks(String imageName, String compiler, List tasks, String runArgs="", registryUrl="https://oejenkinscidockerregistry.azurecr.io", registryName="oejenkinscidockerregistry") {
    exec_with_retry(3,300){
        docker.withRegistry(registryUrl, registryName) {
            def image = docker.image(imageName)
            image.pull()
            image.inside(runArgs) {
                for (task in tasks) {
                    task
                }
            }
        }
    }
}

def azureEnvironment(String task, String imageName = "oetools-deploy:latest") {
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

def runTask(String task) {
    dir("${WORKSPACE}/build") {
        sh """#!/usr/bin/env bash
                set -o errexit
                set -o pipefail
                source /etc/profile
                ${task}
            """
    }
}

def Run(String compiler, String task, String compiler_version = "") {
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
        runTask(task);
    }
}

def deleteRG(List resourceGroups, String imageName = "oetools-deploy:latest") {
    stage("Delete ${resourceGroups.toString()} resource groups") {
        resourceGroups.each { rg ->
            withEnv(["RESOURCE_GROUP=${rg}"]) {
                dir("${WORKSPACE}/.jenkins/provision") {
                    azureEnvironment("./cleanup.sh", imageName)
                }
            }
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
 * Compile open-enclave on Windows platform, generate NuGet package out of it, 
 * install the generated NuGet package, and run samples tests against the installation.
 */
def WinCompilePackageTest(String dirName, String buildType, String hasQuoteProvider, Integer timeoutSeconds, String lviMitigation = 'None', String lviMitigationSkipTests = 'ON', List extra_cmake_args = []) {
    cleanWs()
    checkout scm
    dir(dirName) {
        /*
        In simulation mode, some samples should not be ran or should run simulation mode. 
        For items that should be skipped, see items appended to SAMPLES_LIST under the IF statement with OE_SIMULATION in:
        https://github.com/openenclave/openenclave/blob/master/samples/test-samples.cmake#L54
        For items that should run in simulation mode, check sample Makefiles for target `simulate`
        SIMULATION_SKIP is a "list" of samples to skip in simulation mode.
        SIMULATION_TEST is a "list" of samples to run in simulation mode.
        */
        bat(
            returnStdout: false,
            returnStatus: false,
            script: """
                call vcvars64.bat x64
                setlocal EnableDelayedExpansion
                cmake.exe ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${buildType} -DBUILD_ENCLAVES=ON -DHAS_QUOTE_PROVIDER=${hasQuoteProvider} -DLVI_MITIGATION=${lviMitigation} -DLVI_MITIGATION_SKIP_TESTS=${lviMitigationSkipTests} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCPACK_GENERATOR=NuGet -Wdev ${extra_cmake_args.join(' ')} || exit !ERRORLEVEL!
                ninja.exe || exit !ERRORLEVEL!
                ctest.exe -V -C ${buildType} --timeout ${timeoutSeconds} || exit !ERRORLEVEL!
                cpack.exe -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY || exit !ERRORLEVEL!
                cpack.exe || exit !ERRORLEVEL!
                if exist C:\\oe rmdir /s/q C:\\oe
                nuget.exe install open-enclave -Source %cd% -OutputDirectory C:\\oe -ExcludeVersion
                set CMAKE_PREFIX_PATH=C:\\oe\\open-enclave\\openenclave\\lib\\openenclave\\cmake
                set SIMULATION_SKIP="\\attested_tls\\attestation\\"
                set SIMULATION_TEST="\\debugmalloc\\helloworld\\switchless\\log_callback\\file-encryptor\\pluggable_allocator\\"
                cd C:\\oe\\open-enclave\\openenclave\\share\\openenclave\\samples
                for /d %%i in (*) do (
                    set BUILD=1
                    if ${OE_SIMULATION} equ 1 if "!SIMULATION_SKIP:%%~nxi=!" neq "%SIMULATION_SKIP%" set BUILD=
                    if !BUILD! equ 1 (
                        cd C:\\oe\\open-enclave\\openenclave\\share\\openenclave\\samples\\"%%i"
                        mkdir build
                        cd build
                        cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\\oe_prereqs -DLVI_MITIGATION=${lviMitigation} || exit !ERRORLEVEL!
                        ninja || exit !ERRORLEVEL!
                        if ${OE_SIMULATION} equ 1 if "!SIMULATION_TEST:%%~nxi=!" neq "%SIMULATION_TEST%" (
                            echo "Running %%i with --simulation flag" 
                            ninja simulate || exit !ERRORLEVEL!
                        ) else (
                            ninja run || exit !ERRORLEVEL!
                        )
                    ) else (
                        echo "Skipping %%i as we are in simulation mode."
                    )
                )
            """
        )
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
