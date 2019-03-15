import hudson.slaves.*
import hudson.model.*

env.XENIAL_RG = "oe-deb-test-${BUILD_NUMBER}-1604"
env.BIONIC_RG = "oe-deb-test-${BUILD_NUMBER}-1804"

String dockerBuildArgs(String... args) {
    String argumentString = ""
    for(arg in args) {
        argumentString += " --build-arg ${arg}"
    }
    return argumentString
}

def dockerImage(String tag, String dockerfile = ".jenkins/Dockerfile", String buildArgs = "") {
    checkout scm
    return docker.build(tag, "${buildArgs} -f ${dockerfile} .")
}

def azureEnvironment(String task) {
    node("nonSGX") {
        cleanWs()
        checkout scm
        String buildArgs = dockerBuildArgs("UID=\$(id -u)",
                                           "GID=\$(id -g)",
                                           "UNAME=\$(id -un)",
                                           "GNAME=\$(id -gn)")

        dockerImage("oetools-deploy", ".jenkins/Dockerfile.deploy", buildArgs).inside {
            timeout(60) {
                withCredentials([usernamePassword(credentialsId: 'SERVICE_PRINCIPAL_OSTCLAB',
                                                  passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                                  usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                                 string(credentialsId: 'OSCTLabSubID', variable: 'SUBSCRIPTION_ID'),
                                 string(credentialsId: 'TenantID', variable: 'TENANT_ID')]) {
                    dir('.jenkins/provision') {
                        sh "${task}"
                    }
                }
            }
        }
    }
}

def ACCDeployVM(String agent_name, String agent_type, String region, String resource_group) {
    stage("Deploy ${agent_name}") {
        withEnv(["REGION=${region}", "RESOURCE_GROUP=${resource_group}", "AGENT_NAME=${agent_name}", "AGENT_TYPE=${agent_type}"]) {
            azureEnvironment("./deploy-agent.sh")
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
        timeout(25) {
            azureEnvironment("${script}")
        }
    }
}

def deleteRG() {
    stage("Delete the oe-deb-test resource groups") {
        withEnv(["RESOURCE_GROUP=${env.XENIAL_RG}"]) {
            azureEnvironment("./cleanup.sh")
        }
        withEnv(["RESOURCE_GROUP=${env.BIONIC_RG}"]) {
            azureEnvironment("./cleanup.sh")
        }
    }
}

try {
    ACCDeployVM("oe-deb-test-${BUILD_NUMBER}-1604", "xenial", "eastus", "${env.XENIAL_RG}")
    ACCDeployVM("oe-deb-test-${BUILD_NUMBER}-1804", "bionic", "westeurope", "${env.BIONIC_RG}")

    parallel "OE 16.04 Testing" :          { AccDebTesting("1604", "eastus", "${OE_1604_DEB_URL}") },
             "OE 18.04 Testing" :          { AccDebTesting("1804", "westeurope", "${OE_1804_DEB_URL}") }

} finally {
    deleteRG()
}
