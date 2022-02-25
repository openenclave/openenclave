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
    "acc-ubuntu-20.04":         env.UBUNTU_2004_CUSTOM_LABEL ?: "ACC-2004",
    "acc-v3-ubuntu-20.04":      env.UBUNTU_2004_ICX_CUSTOM_LABEL ?: "ACC-v3-2004",
    "acc-ubuntu-18.04":         env.UBUNTU_1804_CUSTOM_LABEL ?: "ACC-1804",
    "acc-v3-ubuntu-18.04":      env.UBUNTU_1804_ICX_CUSTOM_LABEL ?: "ACC-v3-1804",
    "ubuntu-nonsgx":            env.UBUNTU_NONSGX_CUSTOM_LABEL ?: "nonSGX-ubuntu-2004",
    "windows-nonsgx":           env.WINDOWS_NONSGX_CUSTOM_LABEL ?: "nonSGX-Windows",
    "acc-ubuntu-20.04-vanilla": env.UBUNTU_VANILLA_2004_CUSTOM_LABEL ?: "vanilla-ubuntu-2004",
    "acc-ubuntu-18.04-vanilla": env.UBUNTU_VANILLA_1804_CUSTOM_LABEL ?: "vanilla-ubuntu-1804",
    "acc-win2019-dcap":         env.WINDOWS_2019_DCAP_CUSTOM_LABEL ?: "SGXFLC-Windows-2019-DCAP",
    "acc-v3-win2019-dcap":      env.WINDOWS_2019_DCAP_ICX_CUSTOM_LABEL ?: "ACC-v3-SGXFLC-Windows-2019-DCAP"
]
@Field COMPILER = "clang-10"
