// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/****************************************
* Shared Library for Helpers and Commands
****************************************/

def CmakeArgs(String build_type = "RelWithDebInfo", String code_coverage = "OFF", String debug_malloc = "ON", String lvi_args="", String cmake_args = "") {
    def args = "-G Ninja -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave' -DCPACK_GENERATOR=DEB -DCODE_COVERAGE=${code_coverage} -DUSE_DEBUG_MALLOC=${debug_malloc} -DCMAKE_BUILD_TYPE=${build_type} ${lvi_args} ${cmake_args} -Wdev"
    return args
}

def WaitForAptLock() {
    def aptWait = """
        i=0
        echo "Checking for locks..."
        # Check for locks
        while fuser /var/lib/dpkg/lock > /dev/null 2>&1 ||
              fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1 ||
              fuser /var/lib/apt/lists/lock > /dev/null 2>&1; do
            # Wait up to 600 seconds to lock to be released
            if (( i > 600 )); then
                echo "Timeout waiting for lock."
                exit 1
            fi
            echo "Waiting for apt/dpkg locks..."
            i=\${i++}
            sleep 1
        done
    """
    return aptWait
}

def TestCommand() {
    def testCommand = """
        echo "Running Test Command"
        ctest --output-on-failure --timeout ${globalvars.CTEST_TIMEOUT_SECONDS}
    """
    return testCommand
}

def InstallBuildCommand() {
    def installCommand = """
        echo "Running Install Build Command"
        cpack -G DEB
        ${WaitForAptLock()}
        sudo ninja -v install
    """
    return installCommand
}

def InstallReleaseCommand() {
    def installCommand = """
        echo "Running Install Release Command"
        echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
        wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

        echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list
        wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

        echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
        wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

        ${WaitForAptLock()}
        sudo apt update

        ${WaitForAptLock()}
        sudo apt install -y open-enclave

        echo "Open Enclave SDK version installed"
        apt list --installed | grep open-enclave
    """
    return installCommand
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
        echo "Running Test Samples Command"
        cp -r /opt/openenclave/share/openenclave/samples ~/
        cd ~/samples
        . /opt/openenclave/share/openenclave/openenclaverc
        for i in *; do
            if [[ -d \${i} ]] && [[ -f \${i}/CMakeLists.txt ]]; then
                cd \${i}
                mkdir build
                cd build
                cmake .. ${lvi_args}
                make
                make run
                cd ~/samples
            fi
        done
        cd ~
        rm -rf ~/samples
    """   
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
    bat(
        returnStdout: false,
        returnStatus: false,
        script: """
            call vcvars64.bat x64
            @echo on
            cd C:\\oe\\${oe_package}\\openenclave\\share\\openenclave\\samples
            for /d %%i in (*) do (
                cd "C:\\oe\\${oe_package}\\openenclave\\share\\openenclave\\samples\\%%i"
                mkdir build
                cd build
                ${ninjaBuildCommand(cmakeArgs, "..")}
                ninja run || exit !ERRORLEVEL!
            )
        """
    )
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
 */
def ninjaBuildCommand(String cmake_arguments = "", String build_directory = "${WORKSPACE}") {
    if(isUnix()) {
        return """
            set -x
            cmake ${build_directory} ${cmake_arguments}
            ninja -v
        """
    } else {
        return """
            @echo on
            setlocal EnableDelayedExpansion
            cmake ${build_directory} ${cmake_arguments} || exit !ERRORLEVEL!
            ninja -v || exit !ERRORLEVEL!
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
 * Downloads an Ubuntu Open Enclave release version from GitHub
 *
 * @param release_version  The version of the Open Enclave release to install
 * @param oe_package       Open Enclave package to install
 *                          - "open-enclave" [Default]
 *                          - "open-enclave-hostverify"
 * @param os_id            The distribution name (e.g. Ubuntu)
 * @param os_release       The distribution version without "." (e.g. 1804)
 */
def releaseDownloadLinuxGitHub(String release_version, String oe_package, String os_id, String os_release) {
    sh """#!/bin/bash -x
        CHANGED=0
        valid_url_regex='^https?://[-A-Za-z0-9\\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\\+&@#/%=~_|]\$'
        ${WaitForAptLock()}
        sudo apt-get install -y jq
        urls=\$(curl -sS https://api.github.com/repos/openenclave/openenclave/releases/tags/v${release_version} | jq --raw-output --compact-output '.assets | map(.browser_download_url) | .[]')
        for url in \${urls}; do
            # Check if url is valid
            if echo "\${url}" | grep -E '^https?://[-A-Za-z0-9\\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\\+&@#/%=~_|]\$'; then
                # Filter packages specific to current distribution and version
                if echo "\${url}" | grep "${os_id}_${os_release}_${oe_package}"; then
                    wget --no-verbose --directory-prefix="${release_version}/${os_id} ${os_release}" \${url}
                    if [[ -f "${release_version}/${os_id} ${os_release}/\$(basename \${url})" ]]; then
                        CHANGED=1
                    else
                        echo "[Error] Failed to download from \${url}"
                        exit 1
                    fi
                fi
            else
                echo "[Error] Encountered invalid URL: \${url}"
                exit 1
            fi
        done
        if [[ \${CHANGED} -eq 0 ]]; then
            echo "[Error] No files were downloaded!"
            exit 1
        fi
    """
}

/**
 * Downloads an Ubuntu Open Enclave release version from a pre-defined Azure Blob container or GitHub
 *
 * @param release_version  The version of the Open Enclave release to install
 * @param oe_package       Open Enclave package to install
 *                          - "open-enclave" [Default]
 *                          - "open-enclave-hostverify"
 * @param source           Which source to download Open Enclave from
 *                          - "Azure" to download from the Azure blob storage [Default]
 *                          - "GitHub" to download from the Open Enclave Repository
 * @param os_id            The distribution name (e.g. Ubuntu)
 * @param os_release       The distribution version without "." (e.g. 1804)
 */
def releaseDownloadLinux(String release_version, String oe_package, String source, String os_id, String os_release) {
    // Determine distribution and version
    // Note: lsb_release is only available on Ubuntu.
    if(source == "Azure") {
        // Download from Open Enclave storage container
        azureContainerDownload('releasecandidates', "${release_version}/${os_id} ${os_release}/*", 'openenclavereleaseblobcontainer')
    } else if(source == "GitHub") {
        // Download packages from Open Enclave GitHub repository releaases
        releaseDownloadLinuxGitHub(release_version, oe_package, os_id, os_release)
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
 * @param release_version  The version of the Open Enclave release to install
 * @param oe_package       Open Enclave package to install
 *                         - "open-enclave" [Default]
 *                         - "open-enclave.OEHOSTVERIFY"
 * @param source           Which source to download Open Enclave from
 *                         - "Azure" to download from the Azure blob storage [Default]
 *                         - "GitHub" to download from the Open Enclave Repository
 * @param windows_version  The Windows version caption (output of "wmic os get caption")
 */
def releaseDownloadWindows(String release_version, String oe_package, String source, String windows_version) {
    if(source == "Azure") {
        // Download from Azure storage container
        azureContainerDownload('releasecandidates', "${release_version}/${windows_version}/*", 'openenclavereleaseblobcontainer')
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
 * @param release_version  The version of the Open Enclave release to install
 * @param oe_package       Open Enclave package to install
 *                         - "open-enclave" [Default]
 *                         - "open-enclave-hostverify"
 * @param source           Which source to download Open Enclave from
 *                         - "Azure" to download from the Azure blob storage [Default]
 *                         - "GitHub" to download from the Open Enclave Repository
 */
def releaseInstall(String release_version = null, String oe_package = "open-enclave", String source = "Azure") {
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
        releaseDownloadLinux(release_version, oe_package, source, os_id, os_release)
        // Install Open Enclave package
        sh """
            ${WaitForAptLock()}
            sudo dpkg -i "${release_version}/${os_id} ${os_release}/${os_id}_${os_release}_${oe_package}_${release_version}_amd64.deb"
        """
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
        releaseDownloadWindows(release_version, oe_package, source, windows_version)     
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
