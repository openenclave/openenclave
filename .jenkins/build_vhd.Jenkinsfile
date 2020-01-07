@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240

def buildVHD(String os_type, String version, String imageName) {
    node("nonSGX") {
        stage("${os_type}-${version}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm

                withCredentials([azureStorage(credentialsId: 'oe_jenkins_storage_account',
                                              storageAccountKeyVariable: 'EASTUS_STORAGE_ACCOUNT_KEY',
                                              storageAccountNameVariable: 'EASTUS_STORAGE_ACCOUNT_NAME'),
                                 azureStorage(credentialsId: 'oe_jenkins_storage_account_westeurope',
                                              storageAccountKeyVariable: 'WESTEUROPE_STORAGE_ACCOUNT_KEY',
                                              storageAccountNameVariable: 'WESTEUROPE_STORAGE_ACCOUNT_NAME')]) {
                    withEnv(["REGION=eastus", "DEST_VHD_NAME=${VHD_NAME_PREFIX}-${os_type}-${version}.vhd", "CONTAINER_NAME=disks"]) {
                        dir("${WORKSPACE}/.jenkins/provision") {
                            oe.azureEnvironment("""
                                                packer build -var-file=templates/packer/${os_type}-${version}-variables.json templates/packer/packer-${os_type}.json 2>&1 | tee packer.log
                                                export SOURCE_URI=\$(cat packer.log | grep OSDiskUri: | awk '{print \$2}')
                                                az storage blob copy start --source-uri \$SOURCE_URI --destination-blob \$DEST_VHD_NAME --destination-container \$CONTAINER_NAME --account-key \$EASTUS_STORAGE_ACCOUNT_KEY --account-name \$EASTUS_STORAGE_ACCOUNT_NAME
                                                az storage blob copy start --source-uri \$SOURCE_URI --destination-blob \$DEST_VHD_NAME --destination-container \$CONTAINER_NAME --account-key \$WESTEUROPE_STORAGE_ACCOUNT_KEY --account-name \$WESTEUROPE_STORAGE_ACCOUNT_NAME
                                                blob_status=\$(az storage blob show --name \$DEST_VHD_NAME --container-name \$CONTAINER_NAME \
                                                  --account-key \$WESTEUROPE_STORAGE_ACCOUNT_KEY --account-name \$WESTEUROPE_STORAGE_ACCOUNT_NAME \
                                                  --output json | jq -r .properties.copy.status)
                                                while [ "\${blob_status}" != "success" ]
                                                do
                                                echo Waiting for \$DEST_VHD_NAME to finish copying ...
                                                sleep 10
                                                blob_status=\$(az storage blob show --name \$DEST_VHD_NAME --container-name \$CONTAINER_NAME \
                                                  --account-key \$WESTEUROPE_STORAGE_ACCOUNT_KEY --account-name \$WESTEUROPE_STORAGE_ACCOUNT_NAME \
                                                  --output json | jq -r .properties.copy.status)
                                                done
                                                """, imageName)
                        }
                    }
                }
            }
        }
    }
}

parallel "Build Ubuntu 16.04" : { buildVHD("ubuntu", "16.04", OE_DEPLOY_IMAGE) },
         "Build Ubuntu 18.04" : { buildVHD("ubuntu", "18.04", OE_DEPLOY_IMAGE) },
         "Build Ubuntu nonSGX" : { buildVHD("ubuntu", "nonSGX", OE_DEPLOY_IMAGE) },
         "Build Windows 2016" : { buildVHD("win", "2016", OE_DEPLOY_IMAGE) },
         "Build Windows 2016 DCAP" : { buildVHD("win", "dcap", OE_DEPLOY_IMAGE) },
         "Build Windows 2016 nonSGX" : { buildVHD("win", "nonSGX", OE_DEPLOY_IMAGE) }
