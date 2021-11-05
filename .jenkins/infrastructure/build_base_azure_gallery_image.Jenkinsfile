// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.


library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

def buildLinuxVMBaseImage(String os_type, String os_version) {
    stage('Environment setup') {
        withCredentials([usernamePassword(credentialsId: 'SERVICE_PRINCIPAL_OSTCLAB',
                                        passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                        usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                        string(credentialsId: 'OSCTLabSubID', variable: 'SUBSCRIPTION_ID'),
                        string(credentialsId: 'TenantID', variable: 'TENANT_ID'),
        ]) {
            retry(10) {
                sh """
                    sleep 5
                    ${helpers.WaitForAptLock()}
                    sudo apt-get update
                    sudo apt-get -y install ca-certificates curl apt-transport-https lsb-release gnupg
                    curl -sL https://packages.microsoft.com/keys/microsoft.asc |
                        gpg --dearmor |
                        sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null
                    AZ_REPO=\$(lsb_release -cs)
                    echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ \$AZ_REPO main" |
                        sudo tee /etc/apt/sources.list.d/azure-cli.list
                    ${helpers.WaitForAptLock()}
                    sudo apt-get update
                    sudo apt-get -y install azure-cli
                """
            }
            sh '''
                az login \
                    --service-principal \
                    -u ${SERVICE_PRINCIPAL_ID} \
                    -p ${SERVICE_PRINCIPAL_PASSWORD} \
                    --tenant ${TENANT_ID}
                az account set -s ${SUBSCRIPTION_ID}
            '''
        }
    }
    withEnv([
        "BUILD_RESOURCE_GROUP=jenkins-build-image-base-${os_type}-${os_version}-${GALLERY_IMAGE_VERSION}",
        "BUILD_VM_NAME=VM-${os_type}-${os_version}-${GALLERY_IMAGE_VERSION}",
        "IMAGE_URN=${helpers.getAzureImageUrn(os_type, os_version)}",
        "GALLERY_IMAGE_DEFINITION=${os_type}_${os_version}_LTS_Gen2"
    ]) {
        stage("Create Resource Group") {
            sh """
                az group create --name "${BUILD_RESOURCE_GROUP}" --location "${params.AZURE_REGION}"
            """
        }
        try {
            stage("Create VM") {
                def EXISTING_SUBNET_ID = sh(
                    returnStdout: true,
                    script: """
                        az network vnet subnet show \
                            --resource-group "${JENKINS_RESOURCE_GROUP}" \
                            --name "${JENKINS_SUBNET_NAME}" \
                            --vnet-name "${JENKINS_VNET_NAME}" \
                            --query id \
                            --out tsv
                    """
                ).trim()
                sh """
                    echo "Creating VM"
                    az vm create \
                        --resource-group "${BUILD_RESOURCE_GROUP}" \
                        --location "${params.AZURE_REGION}" \
                        --name "${BUILD_VM_NAME}" \
                        --size Standard_DC2s \
                        --os-disk-size-gb 128 \
                        --subnet "${EXISTING_SUBNET_ID}" \
                        --public-ip-address "" \
                        --authentication-type ssh \
                        --generate-ssh-keys \
                        --image ${env.IMAGE_URN}
                """
                def BUILD_VM_PRIVATE_IP = sh(
                    returnStdout: true,
                    script: """
                        az vm show \
                            --resource-group "${env.BUILD_RESOURCE_GROUP}" \
                            --name "${env.BUILD_VM_NAME}" \
                            --show-details \
                            --query privateIps \
                            --out tsv
                    """
                ).trim()
                withEnv(["BUILD_VM_PRIVATE_IP=${BUILD_VM_PRIVATE_IP}"]) {
                    retry(5) {
                        sh '''
                            sleep 30
                            ssh -o StrictHostKeyChecking=no oeadmin@${BUILD_VM_PRIVATE_IP} \
                                "unset HISTFILE && \
                                while sudo ps aux | grep -E '[a]pt|[d]pkg'; do sleep 5; done"
                        '''
                        sh '''
                            ssh -o StrictHostKeyChecking=no oeadmin@${BUILD_VM_PRIVATE_IP} \
                                "unset HISTFILE && \
                                sudo apt-get update && \
                                sudo apt-get -y install apt-transport-https ca-certificates && \
                                sudo apt-get -y upgrade && \
                                sudo apt-get -y dist-upgrade && \
                                sudo sed -i 's/\\".*\\"/\\"0\\"/' /etc/apt/apt.conf.d/20auto-upgrades && \
                                sudo systemctl disable apt-daily-upgrade.timer && \
                                sudo systemctl disable apt-daily.timer"
                        '''
                    }
                    withCredentials([usernamePassword(credentialsId: JENKINS_USER_CREDS_ID,
                                                    usernameVariable: 'SSH_USERNAME',
                                                    passwordVariable: 'SSH_PASSWORD')
                    ]) {
                        sh '''
                            ssh -o StrictHostKeyChecking=no oeadmin@${BUILD_VM_PRIVATE_IP} \
                                "unset HISTFILE && \
                                sudo echo '${SSH_USERNAME}:${SSH_PASSWORD}' | sudo chpasswd && \
                                sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
                                sudo /usr/sbin/waagent -force -deprovision+user && \
                                sync"
                        '''
                    }
                }
            }
            stage("Generalize VM") {
                sh """
                    echo "Generalize VM"
                    az vm deallocate \
                        --resource-group "${env.BUILD_RESOURCE_GROUP}" \
                        --name "${env.BUILD_VM_NAME}"
                    az vm generalize \
                        --resource-group "${env.BUILD_RESOURCE_GROUP}" \
                        --name "${env.BUILD_VM_NAME}"
                """
            }
            stage("Upload Image") {
                def BUILD_VM_ID = sh(
                    returnStdout: true,
                    script: """
                        az vm show \
                            --resource-group "${env.BUILD_RESOURCE_GROUP}" \
                            --name "${env.BUILD_VM_NAME}" \
                            --query 'id'
                    """
                ).trim()
                sh """
                    echo "Upload Image to Shared Image Gallery"
                    echo "Note: the Shared Image Gallery and Image Definition needs to be created manually"
                    az sig image-version delete \
                        --resource-group "${GALLERY_RESOURCE_GROUP}" \
                        --gallery-name "${GALLERY_NAME}" \
                        --gallery-image-definition "${GALLERY_IMAGE_DEFINITION}" \
                        --gallery-image-version "${GALLERY_IMAGE_VERSION}"
                    az sig image-version create \
                        --resource-group "${GALLERY_RESOURCE_GROUP}" \
                        --gallery-name "${GALLERY_NAME}" \
                        --gallery-image-definition "${GALLERY_IMAGE_DEFINITION}" \
                        --gallery-image-version "${GALLERY_IMAGE_VERSION}" \
                        --managed-image "${BUILD_VM_ID}" \
                        --target-regions ${params.REPLICATION_REGIONS.split(',').join(' ')} \
                        --replica-count 1
                """
            }
        } finally {
            stage("Cleanup Resource Group") {
                sh """
                    az group delete --name "${BUILD_RESOURCE_GROUP}" --yes
                """
            }
        }
    }
}


pipeline {
    agent {
        label globalvars.AGENTS_LABELS["ubuntu-nonsgx"]
    }
    options {
        timeout(time: 90, unit: 'MINUTES')
    }
    parameters {
        string(name: 'REPOSITORY_NAME', defaultValue: 'openenclave/openenclave', description: 'GitHub repository to checkout')
        string(name: 'BRANCH_NAME', defaultValue: 'master', description: 'The branch used to checkout the repository')
        string(name: 'GALLERY_RESOURCE_GROUP', defaultValue: 'OE-Jenkins-Images', description: 'Target resource group used to save the base Azure images')
        string(name: 'OE_DEPLOY_IMAGE', defaultValue: 'oetools-deploy:latest', description: 'Docker image and versions used to run packer')
        string(name: 'AZURE_REGION', defaultValue: 'westeurope', description: 'Images location')
        string(name: 'REPLICATION_REGIONS', defaultValue: 'westeurope,eastus,uksouth,eastus2', description: 'Replication regions for the shared gallery images definitions (comma-separated)')
        string(name: "OECI_LIB_VERSION", defaultValue: 'master', description: 'Version of OE Libraries to use')
    }
    environment {
        JENKINS_USER_CREDS_ID = 'oeadmin-credentials'
        OETOOLS_REPO_CREDENTIALS_ID = 'oejenkinscidockerregistry'
        DOCKER_REGISTRY = 'oejenkinscidockerregistry.azurecr.io'
        JENKINS_RESOURCE_GROUP = 'OE-Jenkins-terraform'
        JENKINS_VNET_NAME = 'OE-Jenkins-terraform-test'
        JENKINS_SUBNET_NAME = 'subnet1'
        GALLERY_NAME = 'Vanilla_Images'
        GALLERY_IMAGE_DATE = helpers.get_date(".")
        GALLERY_IMAGE_VERSION = "${GALLERY_IMAGE_DATE}${BUILD_NUMBER}"
    }
    stages {
        stage('Build') {
            parallel {
                stage("Ubuntu 18.04") {
                    steps {
                        script {
                            buildLinuxVMBaseImage("Ubuntu", "18.04")
                        }
                    }
                }
                stage("Ubuntu 20.04") {
                    steps {
                        script {
                            buildLinuxVMBaseImage("Ubuntu", "20.04")
                        }
                    }
                }
            }
        }
    }
    post {
        always {
            sh """
                az logout || true
                az cache purge
                az account clear
            """
        }
    }
}
