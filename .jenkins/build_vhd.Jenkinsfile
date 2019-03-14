String dockerBuildArgs(String... args) {
    String argumentString = ""
    for(arg in args) {
        argumentString += " --build-arg ${arg}"
    }
    return argumentString
}

def buildOEJenkinsImage(String version) {
    stage("Build Ubuntu ${version} Azure image") {
        node("nonSGX") {
            cleanWs()
            checkout scm
            String buildArgs = dockerBuildArgs("UID=\$(id -u)",
                                               "GID=\$(id -g)",
                                               "UNAME=\$(id -un)",
                                               "GNAME=\$(id -gn)")

            def azure_image = docker.build("oetools-deploy", "${buildArgs} -f .jenkins/Dockerfile.deploy .")
            azure_image.inside {
                timeout(60) {
                    withCredentials([usernamePassword(credentialsId: 'SERVICE_PRINCIPAL_OSTCLAB',
                                                      passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                                      usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                                     string(credentialsId: 'OSCTLabSubID', variable: 'SUBSCRIPTION_ID'),
                                     string(credentialsId: 'TenantID', variable: 'TENANT_ID'),
                                     azureStorage(credentialsId: 'oe_jenkins_storage_account',
                                                  storageAccountKeyVariable: 'EASTUS_STORAGE_ACCOUNT_KEY',
                                                  storageAccountNameVariable: 'EASTUS_STORAGE_ACCOUNT_NAME'),
                                     azureStorage(credentialsId: 'oe_jenkins_storage_account_westeurope',
                                                  storageAccountKeyVariable: 'WESTEUROPE_STORAGE_ACCOUNT_KEY',
                                                  storageAccountNameVariable: 'WESTEUROPE_STORAGE_ACCOUNT_NAME')]) {
                        withEnv(["REGION=eastus", "DEST_VHD_NAME=${VHD_NAME_PREFIX}-${version}.vhd", "CONTAINER_NAME=disks"]) {
                            dir('.jenkins/provision') {
                                sh "packer build -var-file=templates/packer/ubuntu-${version}-variables.json templates/packer/packer.json 2>&1 | tee packer.log"
                                sh """
                                   export SOURCE_URI=\$(cat packer.log | grep OSDiskUri: | awk '{print \$2}')
                                   az storage blob copy start --source-uri \$SOURCE_URI --destination-blob \$DEST_VHD_NAME --destination-container \$CONTAINER_NAME --account-key \$EASTUS_STORAGE_ACCOUNT_KEY --account-name \$EASTUS_STORAGE_ACCOUNT_NAME
                                   az storage blob copy start --source-uri \$SOURCE_URI --destination-blob \$DEST_VHD_NAME --destination-container \$CONTAINER_NAME --account-key \$WESTEUROPE_STORAGE_ACCOUNT_KEY --account-name \$WESTEUROPE_STORAGE_ACCOUNT_NAME
                                   """
                            }
                        }
                    }
                }
            }
        }
    }
}

parallel "Build Ubuntu 16.04" : { buildOEJenkinsImage("16.04") },
         "Build Ubuntu 18.04" : { buildOEJenkinsImage("18.04") }
