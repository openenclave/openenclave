// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

properties(
    [
        buildDiscarder(
            logRotator(
                artifactDaysToKeepStr: '90',
                artifactNumToKeepStr: '180',
                daysToKeepStr: '90',
                numToKeepStr: '180'
            )
        ),
        [$class: 'JobRestrictionProperty'],
        parameters(
            [
                string(name: "REPOSITORY", defaultValue: "openenclave/openenclave"),
                string(name: "BRANCH_NAME", defaultValue: "master"),
                string(name: "DCAP_URL", description: "Intel DCAP Package URL"),
                string(name: "PSW_URL", description: "Intel PSW Package URL"),
                string(name: "OECI_LIB_VERSION", defaultValue: "master", description: 'Version of OE Libraries to use'),
                string(name: "OE_RELEASE_VERSION", description: "Open Enclave Release Version"),
                choice(name: "OE_PACKAGE", defaultValue: "open-enclave", choices: ["open-enclave", "open-enclave-hostverify"], description: "Open Enclave package type to install"),
                choice(name: "RELEASE_SOURCE", choices: ["GitHub", "Azure"], description: "Source to download the OE Release from")
            ]
        )
    ]
)

parallel "Windows Server 2019": { tests.TestIntelRCs(globalvars.AGENTS_LABELS["acc-win2019-dcap"], params.OE_RELEASE_VERSION, params.OE_PACKAGE, params.RELEASE_SOURCE, false, params.DCAP_URL, params.PSW_URL, "-SkipVSInstall") }
// TODO: enable when we have vanilla Windows ACC image
//       "Windows Server 2019 - Upgrade": { tests.TestIntelRCs(globalvars.AGENTS_LABELS["acc-win2019-dcap"], params.OE_RELEASE_VERSION, params.OE_PACKAGE, params.RELEASE_SOURCE, false, params.DCAP_URL, params.PSW_URL, true) }
