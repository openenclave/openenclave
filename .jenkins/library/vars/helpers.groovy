// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/****************************************
* Shared Library for Helpers and Commands
****************************************/

def CmakeArgs(String build_type = "RelWithDebInfo", String code_coverage = "OFF", String debug_malloc = "ON", String lvi_args="", String cmake_args = "") {
    def args = "-G Ninja -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave' -DCPACK_GENERATOR=DEB -DCODE_COVERAGE=${code_coverage} -DUSE_DEBUG_MALLOC=${debug_malloc} -DCMAKE_BUILD_TYPE=${build_type} ${lvi_args} ${cmake_args} -Wdev"
    return args
}

def WaitForAptLock() {
    return """
        counter=0
        max=600
        step=5
        echo "Checking for locks..."
        while sudo fuser /var/lib/dpkg/lock > /dev/null 2>&1 ||
              sudo fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1 ||
              sudo fuser /var/lib/apt/lists/lock > /dev/null 2>&1 ||
              sudo ps aux | grep -E "[a]pt|[d]pkg"; do
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
 * Install Open Enclave dependencies on host machine
 *
 * @param dcap_url      URL of DCAP package, leave blank to use default
 * @param psw_url       URL of PSW package, leave blank to use default
 * @param install_flags Linux: set Ansible environment variables,
 *                      Windows: set additional args for install-windows-prereqs.ps1 script
 * @param build_dir     String that is a path to the directory that contains CMakeList.txt
 *                      Can be relative to current working directory or an absolute path
 */
def dependenciesInstall(String dcap_url = "", String psw_url = "", String install_flags = "", String build_dir = "${WORKSPACE}") {
    if(isUnix()) {
        sh """
            sudo bash ${build_dir}/scripts/ansible/install-ansible.sh
            cp ${WORKSPACE}/scripts/ansible/ansible.cfg ${WORKSPACE}/ansible.cfg
            ansible-playbook ${build_dir}/scripts/ansible/oe-contributors-acc-setup.yml --extra-vars "intel_sgx_w_flc_driver_url=${dcap_url} intel_sgx1_driver_url=${psw_url} ${install_flags}"
            apt list --installed | grep libsgx
            ${WaitForAptLock()}
            sudo apt install -y dkms
        """
    } else {
        if (dcap_url == "" || psw_url == "") {
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
 * @param release_version  The version of the Open Enclave release to install
 * @param oe_package       Open Enclave package to install
 *                          - "open-enclave" [Default]
 *                          - "open-enclave-hostverify"
 * @param os_id            The distribution name (e.g. Ubuntu)
 * @param os_release       The distribution version without "." (e.g. 1804)
 */
def releaseDownloadLinuxGitHub(String release_version, String oe_package, String os_id, String os_release) {
    sh(
        label: "Install pre-requisites",
        script: """
            ${WaitForAptLock()}
            sudo apt-get install -y jq
        """
    )
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
        azureContainerDownload('releasecandidates', "${release_version}/${os_id}_${os_release}/*", 'openenclavereleaseblobcontainer')
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
        def downloadedFiles = releaseDownloadLinux(release_version, oe_package, source, os_id, os_release)
        if(!downloadedFiles) {
            error("[Error] No files were downloaded!")
        } else {
            print(downloadedFiles)
        }
        // Install Open Enclave package
        for(file in downloadedFiles) {
            sh """
                ${WaitForAptLock()}
                sudo dpkg -i "${file}"
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
    if (os_type.toLowerCase() != 'ubuntu' || ! os_version.matches('20.04|18.04')) {
            error("Unsupported OS (${os_type}) or version (${os_version})")
    }
    if (os_version == '20.04') {
        return "Canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest"
    } else if (os_version == '18.04') {
        return "Canonical:UbuntuServer:18_04-lts-gen2:latest"
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
    if ( os_type.equalsIgnoreCase('ubuntu') && os_version.equals('20.04') ) {
        devices.add('/dev/sgx/provision')
        devices.add('/dev/sgx/enclave')
    }
    else if ( os_type.equalsIgnoreCase('ubuntu') && os_version.equals('18.04') ) {
        devices.add('/dev/sgx')
    }
    else {
        error("getDockerSGXDevices(): Unknown OS (${os_type}) or version (${os_version})")
    }
    String returnDevices = ""
    for (device in devices) {
        if ( fileExists("${device}") ) {
            returnDevices += " --device=${device}:${device} "
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
