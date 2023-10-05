// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/************************************
* Shared Library for Global Variables
************************************/

import groovy.transform.Field

@Field GLOBAL_TIMEOUT_MINUTES = 120
@Field CTEST_TIMEOUT_SECONDS = 480
@Field GLOBAL_ERROR = null
@Field AGENTS_LABELS = [
    // ACC VMs
    "acc-ubuntu-20.04":            env.UBUNTU_2004_CUSTOM_LABEL ?: "ACC-2004",
    "acc-v3-ubuntu-20.04":         env.UBUNTU_2004_ICX_CUSTOM_LABEL ?: "ACC-v3-2004",
    "acc-win2019-dcap":            env.WINDOWS_2019_DCAP_CUSTOM_LABEL ?: "SGXFLC-Windows-2019-DCAP",
    "acc-v3-win2019-dcap":         env.WINDOWS_2019_DCAP_ICX_CUSTOM_LABEL ?: "ACC-v3-SGXFLC-Windows-2019-DCAP",
    "acc-win2022-dcap":            env.WINDOWS_2022_DCAP_CUSTOM_LABEL ?: "SGXFLC-Windows-2022-DCAP",
    "acc-v3-win2022-dcap":         env.WINDOWS_2022_DCAP_ICX_CUSTOM_LABEL ?: "ACC-v3-SGXFLC-Windows-2022-DCAP",
    // Non SGX VMs
    "ubuntu-nonsgx":               env.UBUNTU_NONSGX_CUSTOM_LABEL ?: "nonSGX-ubuntu-2004",
    "ubuntu-nonsgx-20.04":         env.UBUNTU_NONSGX_CUSTOM_LABEL ?: "nonSGX-ubuntu-2004",
    "windows-nonsgx":              env.WINDOWS_NONSGX_CUSTOM_LABEL ?: "nonSGX-Windows",
    "windows-2022-nonsgx":          env.WINDOWS_2022_NONSGX_CUSTOM_LABEL ?: "nonSGX-Windows-2022",
    // Plain VMs
    "acc-ubuntu-20.04-vanilla":    env.UBUNTU_VANILLA_2004_CUSTOM_LABEL ?: "vanilla-ubuntu-2004",
    // US-specific ACC VMs
    "acc-ubuntu-20.04-vanilla-us": "vanilla-ubuntu-2004-westus || vanilla-ubuntu-2004-eastus",
    "acc-ubuntu-20.04-us":         "ACC-2004-DC2-westus || ACC-2004-DC2-eastus",
    "acc-win2019-dcap-us":         "SGXFLC-Windows-2019-DCAP-westus || SGXFLC-Windows-2019-DCAP-eastus",
    "acc-win2022-dcap-us":         "SGXFLC-Windows-2022-DCAP-westus || SGXFLC-Windows-2022-DCAP-eastus",
    // Others
    "shared":                      "Jenkins-Shared-DC2"
]
@Field COMPILER = "clang-11"
