// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

GLOBAL_TIMEOUT_MINUTES = 240


def OEPackageTesting(String label, String deb_url) {
    stage("${label} Package Testing") {
        node(label) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                oe.runTask("""
                    wget --tries=30 -nv -O /tmp/open-enclave.deb ${deb_url}
                    for i in {1..30}; do
                        sudo dpkg -i /tmp/open-enclave.deb && break || sleep 15
                    done
                    cp -r /opt/openenclave/share/openenclave/samples/ ./samples
                    source /opt/openenclave/share/openenclave/openenclaverc
                    SAMPLES=`find ./samples/* -maxdepth 0 -type d`
                    for DIR in \$SAMPLES; do
                        pushd \$DIR
                        make build
                        make run
                        popd
                    done
                """)
            }
        }
    }
}


parallel "OE Ubuntu 16.04 Package Testing" : { OEPackageTesting("OE-Nightly-Ubuntu-1604", params.OE_1604_DEB_URL) },
         "OE Ubuntu 18.04 Package Testing" : { OEPackageTesting("OE-Nightly-Ubuntu-1804", params.OE_1804_DEB_URL) }
