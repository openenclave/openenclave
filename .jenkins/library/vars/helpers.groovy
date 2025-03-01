// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/****************************************
* Shared Library for Helpers and Commands
****************************************/

/** Helps create cmake parameters for the build
 * TODO: Check support for Windows tests
 *
 * @param builder                   [string]  The build system to use.
 *                                            Choice of: Ninja, CMake
 * @param build_type                [string]  The build type to use.
 *                                            Choice of: Debug, RelWithDebInfo, Release
 * @param code_coverage             [boolean] Enable code coverage?
 *                                            Default: OFF
 * @param debug_malloc              [boolean] Enable debug malloc?
 *                                            Default: OFF
 * @param lvi_mitigation            [string]  The LVI mitigation to use.
 *                                            Choice of: None, ControlFlow, ControlFlow-Clang, ControlFlow-GNU
 *                                            Default: None
 * @param lvi_mitigation_skip_tests [boolean] Skip LVI mitigation tests?
 *                                            Default: OFF
 * @param use_snmalloc              [boolean] Use snmalloc?
 *                                            Default: OFF
 * @param use_eeid                  [boolean] Use EEID?
 *                                            Default: OFF
 */
def CmakeArgs(Map args) {
    // Check valid builder parameters
    if ((args.builder != 'Ninja') &&
        (args.builder != 'CMake')) {
        throw new Exception("Unsupported builder: ${args.builder}")
    }
    // Set generator for appropriate build system
    def generator = ""
    if (args.builder == 'Ninja') {
        generator = 'Ninja'
    } else if (args.builder == 'CMake') {
        generator = 'Unix Makefiles'
    }
    // Check valid build_type parameters
    if ((args.build_type != 'Debug') &&
        (args.build_type != 'RelWithDebInfo') &&
        (args.build_type != 'Release')) {
        throw new Exception("Unsupported build type: ${args.build_type}")
    }
    // set code_coverage
    def code_coverage = 'OFF'
    if (args.code_coverage) {
        code_coverage = 'ON'
    }
    // set debug_malloc
    def debug_malloc = 'OFF'
    if (args.debug_malloc) {
        debug_malloc = 'ON'
    }
    // Check valid lvi_mitigation parameters
    def lvi_args = ""
    if ((args.lvi_mitigation == 'ControlFlow') ||
        (args.lvi_mitigation == 'ControlFlow-GNU')) {
        lvi_args = "-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin"
    } else if ((args.lvi_mitigation != 'None') &&
               (args.lvi_mitigation != 'ControlFlow-Clang')) {
        throw new Exception("Unsupported LVI mitigation: ${args.lvi_mitigation}")
    }
    // set lvi_mitigation_skip_tests
    def lvi_mitigation_skip_tests = 'OFF'
    if (args.lvi_mitigation_skip_tests) {
        lvi_mitigation_skip_tests = 'ON'
    }
    // set use_snmalloc
    def use_snmalloc = 'OFF'
    if (args.use_snmalloc) {
        use_snmalloc = 'ON'
    }
    // set use_eeid
    def use_eeid = 'OFF'
    if (args.use_eeid) {
        use_eeid = 'ON'
    }
    return "-G '${generator}' -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave' -DCPACK_GENERATOR=DEB -DCODE_COVERAGE=${code_coverage} -DUSE_DEBUG_MALLOC=${debug_malloc} -DCMAKE_BUILD_TYPE=${args.build_type} -DLVI_MITIGATION=${args.lvi_mitigation} -DLVI_MITIGATION_SKIP_TESTS=${lvi_mitigation_skip_tests} ${lvi_args} -DUSE_SNMALLOC=${use_snmalloc} -DWITH_EEID=${use_eeid} -Wdev"
}

def WaitForAptLock() {
    return """
        ${needSudo()}
        counter=0
        max=600
        step=5
        echo "Checking for locks..."
        while \${maybesudo} fuser /var/lib/dpkg/lock > /dev/null 2>&1 ||
              \${maybesudo} fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1 ||
              \${maybesudo} fuser /var/lib/apt/lists/lock > /dev/null 2>&1 ||
              \${maybesudo} ps aux | grep -E "[a]pt|[d]pkg"; do
            # Wait up to 600 seconds to lock to be released
            if (( \${counter} > \${max} )); then
                echo "Timeout waiting for lock."
                exit 1
            fi
            echo "Waiting for apt/dpkg locks..."
            counter=\$((\${counter}+\${step}))
            sleep \${step}
        done
    """
}

/* Runs ctest with specific paramters and retry logic
 *
 * @param regex            [string]  The regex to run matching tests by name
 * @param test_fail_limit  [int]     The maximum number of failed tests before giving up
 *
 * Note: Openssl version 3.0.2 has a known issue with the genrsa command that has a chance to fail.
 *       In Ubuntu 22.04, the latest available openssl version is 3.0.2 via official apt repostories as of 28-02-2025.
 *       https://github.com/openssl/openssl/issues/18321
 * Note: this currently only supports Linux
 */
def TestCommand(String regex='', int test_fail_limit = 10) {
    if (regex != '') {
        regex = '--tests-regex \'${regex}\''
    }
    return """
        try=0
        max_tries=3
        echo "Running Test Command"
        if ! ctest ${regex} --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}; then
            while [ \$try -lt \$max_tries ]; do
                if [[ \$(wc -l < Testing/Temporary/LastTestsFailed.log) -le ${test_fail_limit} ]]; then
                    echo "Retrying failed tests..."
                    try=\$((\$try+1))
                    if ctest ${regex} --rerun-failed --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}; then
                        break
                    fi
                else
                    echo "More than 10 tests failed and is likely not a flaky test issue. Not retrying."
                    exit 8
                fi
            done
        fi
    """
}

def createOpenEnclavePackageCommand() {
    if (isUnix()) {
        return "cpack -G DEB"
    } else {
        return "cpack.exe -D CPACK_NUGET_COMPONENT_INSTALL=ON"
    }
}

def createHostVerifyPackageCommand() {
    if (isUnix()) {
        return "cpack -G DEB -D CPACK_DEB_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY"
    } else {
        return "cpack.exe -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY"
    }
}

def makeInstallCommand() {
    return """
        sudo make install
    """
}

def ninjaInstallCommand() {
    return """
        sudo ninja -v install
    """
}

/**
 * Returns Windows current working directory path
*/
def getWindowsCwd() {
    return powershell(
            script: "(Get-Location).path",
            returnStdout: true
        ).trim()
}

/**
 * Tests Open Enclave samples on *nix systems
 *
 * @param lvi_mitigation  Determines whether tests should be ran with LVI mitigation
 * @param oe_package      Open Enclave package to install
 *                         - "open-enclave" [Default]
 *                         - "open-enclave-hostverify"
 */
def testSamplesLinux(boolean lvi_mitigation, String oe_package) {
    def lvi_args = ""
    if(oe_package == "open-enclave-hostverify") {
        // No host verification tests available during this migration
        return
    }
    if(lvi_mitigation) {
        sh "printf \'%s\\n\' no /usr/local/lvi-mitigation  | sudo /opt/openenclave/bin/scripts/lvi-mitigation/install_lvi_mitigation_bindir"
        lvi_args += "-DLVI_MITIGATION=ControlFlow -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/lvi_mitigation_bin .."
    }
    sh """#!/bin/bash
        set -e
        echo "Running Test Samples Command"
        cp -r /opt/openenclave/share/openenclave/samples ~/
        cd ~/samples
        . /opt/openenclave/share/openenclave/openenclaverc
        if hash cmake 2> /dev/null; then
            echo "INFO: Using cmake to build"
            export BUILD_SYSTEM=CMAKE
        elif hash make 2> /dev/null; then
            echo "INFO: Using make to build"
            export BUILD_SYSTEM=MAKE
        fi
        if [[ -z \${BUILD_SYSTEM+x} ]]; then
            echo "Error: cmake and make not found. Please install either one to proceed"
            exit 1
        fi
        for i in *; do
            if [[ \${BUILD_SYSTEM} == "CMAKE" ]]; then
                if [[ -d \${i} ]] && [[ -f \${i}/CMakeLists.txt ]]; then
                    echo "Running sample: \${i}"
                    cd \${i}
                    mkdir build
                    cd build
                    cmake .. ${lvi_args}
                    make
                    make run
                    cd ~/samples
                fi
            elif [[ \${BUILD_SYSTEM} == "MAKE" ]]; then
                if [[ -d \${i} ]] && [[ -f \${i}/Makefile ]]; then
                    echo "Running sample: \${i}"
                    cd \${i}
                    make build
                    make run
                fi
            else
                echo "Error: unrecognized build system. Either cmake or make must be installed."
                exit 1
            fi
        done
        cd ~
        rm -rf ~/samples
    """   
}

/**
 * Returns the latest Open Enclave release version
 */
def getLatestOpenEnclaveRelease() {
    sh(
        label: "Install pre-requisites",
        script: """#!/usr/bin/env bash
            ${WaitForAptLock()}
            ${needSudo()}
            \${maybesudo} apt-get install -y jq wget curl
        """
    )
    return sh(
        label: "Get latest Open Enclave release",
        script: """#!/bin/bash
            curl -sS https://api.github.com/repos/openenclave/openenclave/releases | jq --raw-output --compact-output '.[0].tag_name'
        """,
        returnStdout: true
    ).trim().replaceFirst('v', '')
}

/** Returns current Windows Intel SGX PSW version */
def getPSWversion() {
    return powershell(
        label: "Intel SGX PSW version",
        script: "(Get-Item C:\\Windows\\System32\\sgx_urts.dll).VersionInfo.ProductVersion",
        returnStdout: true
    ).trim()
}

/** Returns current Windows Intel SGX DCAP version */
def getDCAPversion() {
    return powershell(
        label: "Intel SGX DCAP version",
        script: "(Get-Item C:\\Windows\\System32\\sgx_dcap_ql.dll).VersionInfo.ProductVersion",
        returnStdout: true
    ).trim()
}

/** Checks to see if Windows Intel SGX PSW is installed correctly */
def verifyPSWinstall() {
    def installedVer = powershell(
        label: "Verify Intel SGX PSW installation",
        script: """
            (Get-WmiObject Win32_PnPSignedDriver| select DeviceName, DriverVersion, Manufacturer | where {\$_.DeviceName -like "*Guard Extensions Platform*"}).DriverVersion
        """,
        returnStdout: true
    ).trim()
    def dllVer = getPSWversion()
    if(installedVer != dllVer) {
        print("[Error] Installed PSW version ${installedVer} does not match dll version ${dllVer}")
    }
    assert installedVer == dllVer
}

/**
 * Tests Open Enclave samples on Windows systems
 *
 * @param lvi_mitigation  Determines whether tests should be ran with LVI mitigation
 * @param oe_package      Open Enclave package to install
 *                         - "open-enclave" [Default]
 *                         - "open-enclave.OEHOSTVERIFY"
 */
def testSamplesWindows(boolean lvi_mitigation, String oe_package) {
    // Set flags for LVI mitigation
    def lvi_args = ""
    if(lvi_mitigation) {
        lvi_args += "-DLVI_MITIGATION=ControlFlow -DLVI_MITIGATION_SKIP_TESTS=OFF"
    }
    def cmakeArgs = "-G Ninja \
                    -DNUGET_PACKAGE_PATH=C:\\oe_prereqs \
                    -DCMAKE_PREFIX_PATH=C:\\oe\\${oe_package}\\openenclave\\lib\\openenclave\\cmake ${lvi_args}"
    def samples = [
        "attestation",
        "attested_tls",
        "data-sealing",
        "debugmalloc",
        "file-encryptor",
        "helloworld",
        "host_verify",
        "log_callback",
        "pluggable_allocator",
        "switchless"
    ]
    samples.each { sample ->
        bat(
            returnStdout: false,
            returnStatus: false,
            script: """
                call vcvars64.bat x64
                @echo on
                cd C:\\oe\\${oe_package}\\openenclave\\share\\openenclave\\samples\\${sample}
                mkdir build
                cd build
            """
        )
        dir("C:\\oe\\${oe_package}\\openenclave\\share\\openenclave\\samples\\${sample}\\build") {
            ninjaBuildCommand(cmakeArgs, "C:\\oe\\${oe_package}\\openenclave\\share\\openenclave\\samples\\${sample}")
            bat(
                script: """
                    call vcvars64.bat x64
                    @echo on
                    ninja.exe run
                """
            )
        }
    }
}

/**
 * Tests Open Enclave samples on Unix and Windows systems
 *
 * @param lvi_mitigation  Determines whether tests should be ran with LVI mitigation
 * @param oe_package      Open Enclave package to install
 *                         - "open-enclave" [Default]
 *                         - "open-enclave-hostverify"
 */
def TestSamplesCommand(boolean lvi_mitigation = false, String oe_package = "open-enclave") {
    if(isUnix()) {
        testSamplesLinux(lvi_mitigation, oe_package)
    }
    else {
        if(oe_package == "open-enclave-hostverify") {
            oe_package = "open-enclave.OEHOSTVERIFY"
            // No tests for open-enclave.OEHOSTVERIFY package. Return true to pass stage.
            return True
        }
        testSamplesWindows(lvi_mitigation, oe_package)
    }
}

/**
 * Builds Open Enclave using cmake and Ninja.
 *
 * @param cmake_arguments String of arguments to be passed to cmake
 * @param build_dir       String that is a path to the directory that contains CMakeList.txt
 *                        Can be relative to current working directory or an absolute path
 *
 * Note: Openssl version 3.0.2 has a known issue with the genrsa command that has a chance to fail.
 *       In Ubuntu 22.04, the latest available openssl version is 3.0.2 via official apt repostories as of 28-02-2025.
 *       https://github.com/openssl/openssl/issues/18321
 */
def ninjaBuildCommand(String cmake_arguments = "", String build_directory = "${WORKSPACE}") {
    if(isUnix()) {
        return """
            set -x
            cmake ${build_directory} ${cmake_arguments}
            try=0
            max_tries=3
            set +o pipefail
            while [ \$try -lt \$max_tries ]; do
                if ! (set +e -xo pipefail; ninja -v |& tee build.log); then
                    if grep -q "genrsa: Error generating RSA key" build.log; then
                        echo "Caught genrsa: Error generating RSA key error. Retrying..."
                        try=\$((\$try+1))
                    else
                        echo "Error: ninja build failed. Please check logs."
                        exit 1
                    fi
                else
                    break
                fi
            done
            set -o pipefail
        """
    } else {
        retry(3) {  
            try {
                bat(
                    script: """
                        call vcvars64.bat x64
                        @echo on
                        setlocal EnableDelayedExpansion
                        cmake.exe ${build_directory} ${cmake_arguments} || exit !ERRORLEVEL!
                        ninja.exe -v || exit !ERRORLEVEL!
                    """
                )
            }
            catch(IOException e) {
                println("Caught IOException: ${e}")
                println("An exception was caused by a known issue. Retrying...")
                if (e.getCause()) {
                    println(e.getCause().toString())
                }
                throw e
            }
            catch(Exception e) {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    error("Caught Exception: ${e}")
                }
            }
        }
    }
}

/** Builds Open Enclave using cmake and make
 *
 * @param cmake_arguments String of arguments to be passed to cmake
 * @param build_dir       String that is a path to the directory that contains CMakeList.txt
 *                        Can be relative to current working directory or an absolute path
 */
def makeBuildCommand(String cmake_arguments = "", String build_directory = "${WORKSPACE}") {
    // Note: make -j seems to cause issues where the agent disconnects and is not reconnectable within 2 hours.
    if(isUnix()) {
        return """
            set -x
            cmake ${build_directory} ${cmake_arguments}
            make
        """
    } else {
        return """
            @echo on
            setlocal EnableDelayedExpansion
            cmake ${build_directory} ${cmake_arguments} || exit !ERRORLEVEL!
            make || exit !ERRORLEVEL!
        """
    }
}

/**
 * Download from an Azure Storage Container
 * From https://plugins.jenkins.io/windows-azure-storage/
 *
 * @param container_name          Name of the Azure Storage Container to download from
 * @param file_pattern            File pattern to match (Ant glob syntax)
 * @param storage_credentials_id  Jenkins credentials id to use to authenticate with Azure Storage
 */
def azureContainerDownload(String container_name, String file_pattern, String storage_credentials_id) {
    azureDownload(
        containerName: container_name,
        downloadType: 'container',
        includeArchiveZips: true,
        includeFilesPattern: file_pattern,
        storageCredentialId: storage_credentials_id
    )
}

/**
 * Install Open Enclave dependencies on host machine
 *
 * @param dcap_url        URL of DCAP package, leave blank to use default
 * @param local_repo_path Local file path to the Intel SGX repository
 * @param install_flags   Linux: set Ansible environment variables,
 *                        Windows: set additional args for install-windows-prereqs.ps1 script
 * @param build_dir       String that is a path to the directory that contains CMakeList.txt
 *                        Can be relative to current working directory or an absolute path
 */
def dependenciesInstall(String dcap_url = "", local_repo_path = "", String install_flags = "", String build_dir = "${WORKSPACE}") {
    if(isUnix()) {
        sh """#!/usr/bin/env bash
            sudo bash ${build_dir}/scripts/ansible/install-ansible.sh
            cp ${WORKSPACE}/scripts/ansible/ansible.cfg ${WORKSPACE}/ansible.cfg
            ${WaitForAptLock()}
            ${needSudo()}
            \${maybesudo} apt install -y dkms
        """
        if (local_repo_path) {
            sh """
                ansible-playbook ${build_dir}/scripts/ansible/oe-contributors-acc-setup.yml \
                  --extra-vars "intel_sgx_apt_repository=file://${local_repo_path} intel_sgx_apt_repository_config=\'trusted=yes arch=amd64\' ${install_flags}"
            """
        } else {
            sh """
                ansible-playbook ${build_dir}/scripts/ansible/oe-contributors-acc-setup.yml --extra-vars "${install_flags}"
            """
        }
        sh 'apt list --installed | grep libsgx'
        sh 'ls -l /usr/lib/x86_64-linux-gnu | grep libsgx'
    } else {
        if (dcap_url == "") {
            powershell """#Requires -RunAsAdministrator
                ${build_dir}\\scripts\\install-windows-prereqs.ps1 -InstallPath C:\\oe_prereqs -LaunchConfiguration SGX1FLC -DCAPClientType None ${install_flags}
            """
        } else {
            powershell """#Requires -RunAsAdministrator
                ${build_dir}\\scripts\\install-windows-prereqs.ps1 -IntelDCAPURL "${dcap_url}" -IntelDCAPHash "" -InstallPath C:\\oe_prereqs -LaunchConfiguration SGX1FLC -DCAPClientType None ${install_flags}
            """
        }
        verifyPSWinstall()
        print("PSW version: ${getPSWversion()} \nDCAP version: ${getDCAPversion()}")
    }
}

/**
 * Downloads an Ubuntu Open Enclave release version from GitHub and returns a list of downloaded files
 *
 * @param release_version  The version of the Open Enclave release to install. Examples:
 *                          - latest
 *                          - 0.19.8
 * @param oe_package       Open Enclave package to install
 *                          - "open-enclave" [Default]
 *                          - "open-enclave-hostverify"
 * @param os_id            The distribution name (e.g. Ubuntu)
 * @param os_release       The distribution version without "." (e.g. 2004)
 */
def releaseDownloadLinuxGitHub(String release_version, String oe_package, String os_id, String os_release) {
    sh(
        label: "Install pre-requisites",
        script: """#!/usr/bin/env bash
            ${WaitForAptLock()}
            ${needSudo()}
            \${maybesudo} apt-get install -y jq wget curl
        """
    )
    if(release_version == 'latest') {
        release_version = getLatestOpenEnclaveRelease()
        println "releaseDownloadLinuxGithub: found ${release_version} as the latest release"
    }
    def downloadedFiles = sh(
        label: "Download files from GitHub using regex ${os_id}(_|-)${os_release}(_|-)${oe_package}(_|-)${release_version}",
        script: """#!/bin/bash
            valid_url_regex='^https?://[-A-Za-z0-9\\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\\+&@#/%=~_|]\$'
            urls=\$(curl -sS https://api.github.com/repos/openenclave/openenclave/releases/tags/v${release_version} | jq --raw-output --compact-output '.assets | map(.browser_download_url) | .[]')
            for url in \${urls}; do
                # Check if url is valid
                if echo "\${url}" | grep -qE '^https?://[-A-Za-z0-9\\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\\+&@#/%=~_|]\$'; then
                    # Filter packages specific to current distribution and version
                    if echo "\${url}" | grep -qiE '${os_id}(_|-)${os_release}(_|-)${oe_package}(_|-)${release_version}'; then
                        wget --no-verbose --directory-prefix="${release_version}/${os_id}_${os_release}" \${url}
                        if [[ -f "${release_version}/${os_id}_${os_release}/\$(basename \${url})" ]]; then
                            echo "${release_version}/${os_id}_${os_release}/\$(basename \${url})"
                        fi
                    fi
                fi
            done
        """,
        returnStdout: true
    ).trim().tokenize('\n')
    if(!downloadedFiles) {
        print("No files were downloaded!")
        return null
    } else {
        return downloadedFiles
    }
}

/**
 * Downloads an Ubuntu Open Enclave release version from a pre-defined Azure Blob container or GitHub
 *
 * @param release_version         The version of the Open Enclave release to install
 * @param oe_package              Open Enclave package to install
 *                                 - "open-enclave" [Default]
 *                                 - "open-enclave-hostverify"
 * @param source                  Which source to download Open Enclave from
 *                                 - "Azure" to download from the Azure blob storage [Default]
 *                                 - "GitHub" to download from the Open Enclave Repository
 * @param os_id                   The distribution name (e.g. Ubuntu)
 * @param os_release              The distribution version without "." (e.g. 2004)
 * @param storage_credentials_id  [Optional] Jenkins storage account credential id
 * @param storage_blob            [Optional] The name of the blob in the Azure storage account
 */
def releaseDownloadLinux(String release_version, String oe_package, String source, String os_id, String os_release, String storage_credentials_id = "", String storage_blob = "") {
    // Determine distribution and version
    // Note: lsb_release is only available on Ubuntu.
    if(source == "Azure") {
        // Download from Open Enclave storage container
        azureContainerDownload(storage_blob, "${release_version}/${os_id}_${os_release}/*", storage_credentials_id)
        sh """
            find ${release_version}/${os_id}_${os_release} -name "*"
        """
        return sh(
            script: """
                find ${release_version}/${os_id}_${os_release} -name "*${oe_package}?${release_version}*"
            """,
            returnStdout: true
        ).trim().tokenize('\n')
    } else if(source == "GitHub") {
        // Download packages from Open Enclave GitHub repository releaases
        return releaseDownloadLinuxGitHub(release_version, oe_package, os_id, os_release)
    } else {
        error("[Error] Invalid Open Enclave source defined!")

    }
}

/**
 * Downloads a Windows Open Enclave release version from GitHub
 *
 * @param release_version  The version of the Open Enclave release to install
 * @param oe_package       Open Enclave package to install
 *                         - "open-enclave" [Default]
 *                         - "open-enclave.OEHOSTVERIFY"
 */
def releaseDownloadWindowsGitHub(String release_version, String oe_package) {
    def cwd = getWindowsCwd()
    powershell """
        \$changed = \$false
        # Initialize IE so subsequent Invoke-RestMethod and Invoke-WebRequest do not fail
        Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Internet Explorer\\Main" -Name "DisableFirstRunCustomize" -Value 1
        \$json = Invoke-RestMethod https://api.github.com/repos/openenclave/openenclave/releases/tags/v${release_version}
        Foreach (\$asset in \$json.assets) {
            # Download release assets that are nuget packages
            if (\$asset.browser_download_url -match "https?://.*/${oe_package}\\.${release_version}\\.nupkg") {
                Write-Output "Downloading ${cwd}\\\$(\$asset.name) from \$(\$asset.browser_download_url)"
                Invoke-WebRequest \$asset.browser_download_url -outFile \$asset.name -passThru
                if (Test-Path "${cwd}\\\$(\$asset.name)" -PathType leaf) {
                    Write-Output "Downloaded ${cwd}\\\$(\$asset.name)"
                    \$changed = \$true
                } else {
                    Throw "[Error] Failed to download from \$(\$asset.browser_download_url)"
                }
            } else {
                Write-Output "Skipping \$(\$asset.browser_download_url)"
            }
        }
        if (!\$changed) {
            Throw "[Error] No files were downloaded!"
        }
    """
}

/**
 * Downloads a Windows Open Enclave release version from a pre-defined Azure Blob container or GitHub
 *
 * @param release_version         The version of the Open Enclave release to install
 * @param oe_package              Open Enclave package to install
 *                                - "open-enclave" [Default]
 *                                - "open-enclave.OEHOSTVERIFY"
 * @param source                  Which source to download Open Enclave from
 *                                - "Azure" to download from the Azure blob storage [Default]
 *                                - "GitHub" to download from the Open Enclave Repository
 * @param windows_version         The Windows version caption (output of "wmic os get caption")
 * @param storage_credentials_id  [Optional] Jenkins storage account credential id
 * @param storage_blob            [Optional] The name of the blob in the Azure storage account
 */
def releaseDownloadWindows(String release_version, String oe_package, String source, String windows_version, String storage_credentials_id = "", String storage_blob = "") {
    if(source == "Azure") {
        // Download from Azure storage container
        azureContainerDownload(storage_blob, "${release_version}/${windows_version}/*", storage_credentials_id)
    } else if(source == "GitHub") {
        // Download nuget packages from Open Enclave GitHub repository releaases
        releaseDownloadWindowsGitHub(release_version, oe_package)
    } else {
        error("[Error] Invalid Open Enclave source defined!")
    }
}

/**
 * Downloads and installs an Open Enclave release version for either Windows or Ubuntu
 * Warning: this function must not be called within a shell otherwise a null command would be ran after this function completes.
 *
 * @param release_version         The version of the Open Enclave release to install. Examples:
 *                                - latest (when source=GithHub)
 *                                - 0.19.8
 * @param oe_package              Open Enclave package to install
 *                                - "open-enclave" [Default]
 *                                - "open-enclave-hostverify"
 * @param source                  Which source to download Open Enclave from
 *                                - "Azure" to download from the Azure blob storage [Default]
 *                                - "GitHub" to download from the Open Enclave Repository
 * @param storage_credentials_id  [Optional] Jenkins storage account credential id
 * @param storage_blob            [Optional] The name of the blob in the Azure storage account
 */
def releaseInstall(String release_version = null, String oe_package = "open-enclave", String source = "Azure", String storage_credentials_id = "", String storage_blob = "") {
    // Check parameters are valid
    if(!release_version) {
        error("[Error] Invalid Open Enclave release version defined!")
    }
    if(!["open-enclave", "open-enclave-hostverify"].contains(oe_package)) {
        error("[Error] Invalid Open Enclave package defined!")
    }
    if(!["Azure", "GitHub"].contains(source)) {
        error("[Error] Invalid Open Enclave source defined!")
    }
    // For *nix
    if(isUnix()) {
        sh """#!/usr/bin/env bash
            ${needSudo()}
            ${WaitForAptLock()}
            \${maybesudo} apt update
            \${maybesudo} apt-get install -y lsb-release
        """
        // Get distribution name
        def os_id = sh(
                script: "lsb_release --id --short",
                returnStdout: true
            ).trim()
        // Get distribution version
        def os_release = sh(
                script: "lsb_release --release --short | sed 's/\\.//'",
                returnStdout: true
            ).trim()
        // Download Open Enclave package
        def downloadedFiles = releaseDownloadLinux(release_version, oe_package, source, os_id, os_release, storage_credentials_id, storage_blob)
        if(!downloadedFiles) {
            error("[Error] No files were downloaded!")
        } else {
            print(downloadedFiles)
        }
        // Install Open Enclave package
        for(file in downloadedFiles) {
            sh """#!/usr/bin/env bash
                ${WaitForAptLock()}
                ${needSudo()}
                \${maybesudo} dpkg -i "${file}"
            """
        }
    // For Windows
    } else {
        // Determine Windows installation type
        def windows_version = bat(
            script: """
                @echo off
                wmic os get caption | find /v "Caption"
                """,
            returnStdout: true
        ).trim()
        // Get current working directory path
        def cwd = getWindowsCwd()
        // Override oe_package name scheme for Host Verify
        if(oe_package == "open-enclave-hostverify") {
            oe_package = "open-enclave.OEHOSTVERIFY"
        }
        // Download Open Enclave package
        releaseDownloadWindows(release_version, oe_package, source, windows_version, storage_credentials_id, storage_blob)     
        // Set nuget flags
        def nuget_flags = "-OutputDirectory C:\\oe -ExcludeVersion"
        if(source == "Azure") {
            nuget_flags += " -Source \"${cwd}\\${release_version}\\${windows_version}\""
        } else if(source == "GitHub") {
            nuget_flags += " -Source \"${cwd}\""
        }
        // Add additional prerelease flag for release candidates if applicable
        if(release_version.contains('-rc')) {
            nuget_flags += " -prerelease"
        }
        // Install Open Enclave package
        powershell """
            nuget.exe install \"${oe_package}\" ${nuget_flags}
        """
    }
}

/**
 * Get today's date in YYYYMMDD format
 *
 * @param delimiter  Optional argument to place a delimiter between YYYY, MM, and DD.
 */
def get_date(String delimiter = "") {
    return (
        LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy")) +
        delimiter +
        LocalDateTime.now().format(DateTimeFormatter.ofPattern("MM")) +
        delimiter +
        LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd"))
    )
}

/* Returns Azure Image URNs for OS type
 *
 * @param os_type  The OS distribution (Currently only "ubuntu")
 * @param os_version The OS distribution version ("18.04", "20.04")
 */
 def getAzureImageUrn(String os_type, String os_version) {
    if (os_type.toLowerCase() != 'ubuntu') {
        error("Unsupported OS: ${os_type}")
    }
    if (os_version == '22.04') {
        return "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest"
    } else if (os_version == '20.04') {
        return "Canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest"
    } else if (os_version == '18.04') {
        return "Canonical:UbuntuServer:18_04-lts-gen2:latest"
    } else {
        error("Unsupported OS version: ${os_version}")
    }
 }

/* Returns codename given release version (eg. 20.04)
 *
 * @param os_version The OS distribution version ("18.04", "20.04")
 */
 def getUbuntuCodename(String os_version) {
    switch(os_version) {
        case "18.04": return "bionic"
        case "20.04": return "focal"
        case "22.04": return "jammy"
    }
 }

/*
 * Determine correct Intel SGX devices to mount for Docker
 * Returns in the format of --device=<DEVICE1> --device=<DEVICE2>...
 *   Note: This is really only necessary as Ubuntu 20.04 has SGX 
 *   driver 1.41 and Ubuntu 18.04 has an older version
 *
 * @param os_type     Host Operating System Distribution (e.g. Ubuntu)
 * @param os_version  Host Operating System Version (e.g. 20.04)
 */
def getDockerSGXDevices(String os_type, String os_version) {
    def devices = []
    if (os_type.equalsIgnoreCase('ubuntu')) {
        if (os_version.equals('18.04')) {
            devices.add('/dev/sgx')
        } else {
            devices.add('/dev/sgx_provision')
            devices.add('/dev/sgx_enclave')
        }
    } else {
        error("getDockerSGXDevices: Unknown OS: ${os_type}")
    }
    String returnDevices = ""
    for (device in devices) {
        if ( fileExists("${device}") ) {
            returnDevices += " --device=${device}:${device} "
        } else {
            error("getDockerSGXDevices: ${device} does not exist!")
        }
    }
    return returnDevices
}

/**
 * Returns the Ubuntu release version (E.g. "18.04")
 */
def getUbuntuReleaseVer() {
    sh(
        returnStdout: true,
        script: 'lsb_release -rs'
    ).trim()
}

/**
 * Returns current git commit id
 */
def get_commit_id() {
    return sh(script: "git rev-parse --short HEAD", returnStdout: true).tokenize().last()
}

/**
 * Returns apt package versions inside Docker container, or None
 *
 * @param docker_image  Docker image[:tag]
 * @param package       Apt package name
 */
def dockerGetAptPackageVersion(String docker_image, String apt_package) {
    version = sh(
        script: "docker run ${docker_image} apt list --installed 2>/dev/null | grep ${apt_package} | awk \'{print \$2}\'",
        returnStdout: true
    ).trim()
    if ( !version ) { version = "N/A" }
    return version
}

def oeCheckoutScm(String PULL_REQUEST_ID) {
    /* If a build was triggered with params.PULL_REQUEST_ID set, then we are building a PR.
    * In this case, we need to checkout the PR merge head.
    * Otherwise we are building a branch and the branch is already checked out by the SCM plugin.
    */
    if ( PULL_REQUEST_ID != null && PULL_REQUEST_ID != "" ) {
        cleanWs()
        checkout([$class: 'GitSCM',
            branches: [[name: "pr/${PULL_REQUEST_ID}"]],
            doGenerateSubmoduleConfigurations: false,
            extensions: [[ $class: 'SubmoduleOption',
                           parentCredentials: true,
                           reference: '',
                           disableSubmodules: false,
                           recursiveSubmodules: true,
                           trackingSubmodules: false,
                           timeout: 30,
                           shallow: true,
                           depth: 1
            ]],
            userRemoteConfigs: [[
                url: 'https://github.com/openenclave/openenclave',
                refspec: "+refs/pull/${PULL_REQUEST_ID}/merge:refs/remotes/origin/pr/${PULL_REQUEST_ID}"
            ]]
        ])
    } else {
        checkout scm
    }
}

/**
 * Use oeutil to generate certs
 *
 * @param oeutil_path  Path to oeutil binary (default: "./output/bin/oeutil")
 * @param format       Format of the certificate (or report, or evidence)
 * @param outfile      Output file (default: "")
 * @param endorsements File to output endorsements to (default: "")
 * @param quoteproc    Use SGX in-process or out-of-process quoting (default: "")
 * @param verify       Verify the certificate (default: true)
 * @param verbose      Verbose output (default: false)
 */
def oeutilGenCert(String format, String oeutil_path="./output/bin/oeutil", String outfile="", String endorsements="", String quoteproc="", boolean verify=true, boolean verbose=false) {
    def cmd = "${oeutil_path} gen --format ${format}"
    if (outfile) {
        cmd += " --out ${outfile}"
    }
    if (endorsements) {
        cmd += " --endorsements ${endorsements}"
    }
    if (quoteproc) {
        cmd += " --quote-proc ${quoteproc}"
    }
    if (verify) {
        cmd += " --verify"
    }
    if (verbose) {
        cmd += " --verbose"
    }
    // SGX quote-ex init can sometimes return SGX_ERROR_SERVICE_TIMEOUT.
    // Subsequent tries should not have this issue.
    return """
        # In case of failure we want to continue on to retry
        set +x
        attempt=1
        max_attempts=10
        while [ \${attempt} -le \${max_attempts} ]; do
            ${cmd}
            # Check for general failure
            if [ \$? -ne 0 ]; then
                attempt=\$((\${attempt}+1))
            # Check if outfile was created, if one is defined
            elif [ "${outfile}" ] && [ ! -f "${outfile}" ]; then
                attempt=\$((\${attempt}+1))
            else
                break
            fi
            if [ \${attempt} -gt \${max_attempts} ]; then
                echo "Failed to generate certificate after \${max_attempts} tries"
                echo "oeutil command: ${cmd}"
            fi
            sleep 3
        done
    """
}

/* Determines if sudo is needed based on current uid.
 * This allows flexibility in using the same commands between VMs and containers.
 * To use this function, use \${maybesudo} in place of sudo
 * When Jenkins uses sh without #!/bin/bash, uid is not set so we default to 9999
 */
def needSudo() {
    return """
        if [ \${UID:-9999} -ne 0 ]; then
            maybesudo="sudo"
        else
            maybesudo=""
        fi
    """
}
