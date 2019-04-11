@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

XENIAL_RG = "oe-deb-test-${BUILD_NUMBER}-1604"
BIONIC_RG = "oe-deb-test-${BUILD_NUMBER}-1804"

def ACCDeployVM(String agent_name, String agent_type, String region, String resource_group, String vhd_url) {
    stage("Deploy ${agent_name}") {
        node("nonSGX") {
            cleanWs()
            checkout scm
            withEnv(["REGION=${region}", "RESOURCE_GROUP=${resource_group}", "AGENT_NAME=${agent_name}", "AGENT_TYPE=${agent_type}", "VHD_URL=${vhd_url}"]) {
                oe.azureEnvironment("./deploy-agent.sh")
            }
        }
    }
}

def AccDebTesting(String version, String region, String deb_url) {
    def test_deb_script = """\
        wget --tries=30 -nv -O /tmp/open-enclave.deb ${deb_url} && \
        for i in {1..30}; do sudo dpkg -i /tmp/open-enclave.deb && break || sleep 15; done && \
        cp -r /opt/openenclave/share/openenclave/samples/ ./samples && \
        source /opt/openenclave/share/openenclave/openenclaverc && \
        cd ./samples && \
        make world"""

    def script = """\
        az login --service-principal -u \${SERVICE_PRINCIPAL_ID} -p \${SERVICE_PRINCIPAL_PASSWORD} --tenant \${TENANT_ID} --output table && \
        az account set --subscription \${SUBSCRIPTION_ID} && \
        az keyvault secret show --vault-name oe-ci-test-kv --name id-rsa-oe-test | jq -r .value | base64 -d > id_rsa && \
        chmod 600 id_rsa && \
        ssh -o StrictHostKeyChecking=no -i id_rsa \
        azureuser@oe-deb-test-${BUILD_NUMBER}-${version}.${region}.cloudapp.azure.com '${test_deb_script}' """

    stage("OE Nightly Package Testing ${version}") {
        node("nonSGX") {
            cleanWs()
            checkout scm
            oe.azureEnvironment("${script}")
        }
    }
}

def cleanup(){
    node("nonSGX") {
        cleanWs()
        checkout scm
        oe.deleteRG([XENIAL_RG, BIONIC_RG])
    }
}

try {
    parallel "Deploy Ubuntu 16.04" :    { ACCDeployVM(XENIAL_RG, "xenial", "eastus", XENIAL_RG, "${VHD_URL_XENIAL}") },
             "Deploy Ubuntu 18.04" :    { ACCDeployVM(BIONIC_RG, "bionic", "westeurope", BIONIC_RG, "${VHD_URL_BIONIC}") }

    parallel "OE 16.04 Testing" :       { AccDebTesting("1604", "eastus", "${OE_1604_DEB_URL}") },
             "OE 18.04 Testing" :       { AccDebTesting("1804", "westeurope", "${OE_1804_DEB_URL}") }

} finally {
    cleanup()
}
