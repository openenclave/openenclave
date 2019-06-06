@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

// The below timeout is set in minutes
GLOBAL_TIMEOUT = 240

def buildVHD(String version) {
    node("nonSGX") {
        timeout(GLOBAL_TIMEOUT) {
            cleanWs()
            checkout scm

            withCredentials([azureStorage(credentialsId: 'oe_jenkins_storage_account',
                                          storageAccountKeyVariable: 'EASTUS_STORAGE_ACCOUNT_KEY',
                                          storageAccountNameVariable: 'EASTUS_STORAGE_ACCOUNT_NAME'),
                             azureStorage(credentialsId: 'oe_jenkins_storage_account_westeurope',
                                          storageAccountKeyVariable: 'WESTEUROPE_STORAGE_ACCOUNT_KEY',
                                          storageAccountNameVariable: 'WESTEUROPE_STORAGE_ACCOUNT_NAME')]) {
                withEnv(["REGION=eastus", "DEST_VHD_NAME=${VHD_NAME_PREFIX}-${version}.vhd", "CONTAINER_NAME=disks"]) {
                    dir("${WORKSPACE}/.jenkins/provision") {
                        oe.azureEnvironment("""
                                            packer build -var-file=templates/packer/ubuntu-${version}-variables.json templates/packer/packer.json 2>&1 | tee packer.log
                                            export SOURCE_URI=\$(cat packer.log | grep OSDiskUri: | awk '{print \$2}')
                                            az storage blob copy start --source-uri \$SOURCE_URI --destination-blob \$DEST_VHD_NAME --destination-container \$CONTAINER_NAME --account-key \$EASTUS_STORAGE_ACCOUNT_KEY --account-name \$EASTUS_STORAGE_ACCOUNT_NAME
                                            az storage blob copy start --source-uri \$SOURCE_URI --destination-blob \$DEST_VHD_NAME --destination-container \$CONTAINER_NAME --account-key \$WESTEUROPE_STORAGE_ACCOUNT_KEY --account-name \$WESTEUROPE_STORAGE_ACCOUNT_NAME
                                            """)
                    }
                }
            }
        }
    }
}

parallel "Build Ubuntu 16.04" : { buildVHD("16.04") },
         "Build Ubuntu 18.04" : { buildVHD("18.04") }
