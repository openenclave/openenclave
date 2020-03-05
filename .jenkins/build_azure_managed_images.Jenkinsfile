@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240

OETOOLS_REPO = "oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIALS_ID = "oejenkinscidockerregistry"

def buildManagedImage(String os_type, String version) {
    node("nonSGX") {
        stage("${os_type}-${version}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def managed_image_name_id
                if (params.IMAGE_ID) {
                    managed_image_name_id = params.IMAGE_ID
                } else {
                    managed_image_name_id = sh(script: "git rev-parse --short HEAD", returnStdout: true).tokenize().last()
                }
                withCredentials([usernamePassword(credentialsId: OETOOLS_REPO_CREDENTIALS_ID,
                                                  usernameVariable: "DOCKER_USER_NAME",
                                                  passwordVariable: "DOCKER_USER_PASSWORD")]) {
                    withEnv(["DOCKER_REGISTRY=${OETOOLS_REPO}",
                             "MANAGED_IMAGE_NAME_ID=${managed_image_name_id}"]) {
                        def cmd = ("packer build -force " +
                                    "-var-file=${WORKSPACE}/.jenkins/provision/templates/packer/azure_managed_image/${os_type}-${version}-variables.json " +
                                    "${WORKSPACE}/.jenkins/provision/templates/packer/azure_managed_image/packer-${os_type}.json")
                        oe.azureEnvironment(cmd, params.OE_DEPLOY_IMAGE)
                    }
                }
            }
        }
    }
}

parallel "Build Ubuntu 16.04"              : { buildManagedImage("ubuntu", "16.04") },
         "Build Ubuntu 18.04"              : { buildManagedImage("ubuntu", "18.04") },
         "Build RHEL 8"                    : { buildManagedImage("rhel", "8") },
         "Build Windows 2016 SGX1"         : { buildManagedImage("win", "2016-SGX") },
         "Build Windows 2016 SGX1FLC DCAP" : { buildManagedImage("win", "2016-SGX-DCAP") },
         "Build Windows 2016 nonSGX"       : { buildManagedImage("win", "2016-nonSGX") }
