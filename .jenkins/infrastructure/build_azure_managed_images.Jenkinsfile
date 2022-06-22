// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

GLOBAL_TIMEOUT_MINUTES = 480

JENKINS_USER_CREDS_ID = 'oeadmin-credentials'
OETOOLS_REPO = 'oejenkinscidockerregistry.azurecr.io'
OETOOLS_REPO_CREDENTIALS_ID = 'oejenkinscidockerregistry'
SERVICE_PRINCIPAL_CREDENTIALS_ID = 'SERVICE_PRINCIPAL_OSTCLAB'
AZURE_IMAGES_MAP = [
    "win2019": [
        "image": "MicrosoftWindowsServer:WindowsServer:2019-datacenter-gensecond:latest",
        "generation": "V2"
    ]
]
OS_NAME_MAP = [
    "win2019": "Windows Server 2019",
    "ubuntu":  "Ubuntu",
]

def buildLinuxManagedImage(String os_type, String version, String managed_image_name_id, String gallery_image_version) {
    stage('Check Prerequisites') {
        retry(10) {
            sh """#!/bin/bash
                sleep 5
                curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
                sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com \$(lsb_release -cs) main"
                ${helpers.WaitForAptLock()}
                sudo apt-get update && sudo apt-get install packer
            """
        }
    }
    stage("${OS_NAME_MAP[os_type]} ${version} Build") {
        withEnv([
                "DOCKER_REGISTRY=${OETOOLS_REPO}",
                "MANAGED_IMAGE_NAME_ID=${managed_image_name_id}",
                "GALLERY_IMAGE_VERSION=${gallery_image_version}",
                "RESOURCE_GROUP=${params.RESOURCE_GROUP}",
                "GALLERY_NAME=${params.GALLERY_NAME}"]) {
            stage("Run Packer Job") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    withCredentials([
                            usernamePassword(credentialsId: JENKINS_USER_CREDS_ID,
                                             usernameVariable: "SSH_USERNAME",
                                             passwordVariable: "SSH_PASSWORD"),
                            usernamePassword(credentialsId: OETOOLS_REPO_CREDENTIALS_ID,
                                             usernameVariable: "DOCKER_USER_NAME",
                                             passwordVariable: "DOCKER_USER_PASSWORD"),
                            usernamePassword(credentialsId: SERVICE_PRINCIPAL_CREDENTIALS_ID,
                                             passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                             usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                            string(credentialsId: 'openenclaveci-subscription-id', variable: 'SUBSCRIPTION_ID'),
                            string(credentialsId: 'TenantID', variable: 'TENANT_ID')]) {
                        sh '''#!/bin/bash
                            az login --service-principal -u ${SERVICE_PRINCIPAL_ID} -p ${SERVICE_PRINCIPAL_PASSWORD} --tenant ${TENANT_ID}
                            az account set -s ${SUBSCRIPTION_ID}
                        '''
                        retry(5) {
                            sh """#!/bin/bash
                                packer build -force \
                                    -var-file=${WORKSPACE}/.jenkins/infrastructure/provision/templates/packer/azure_managed_image/${os_type}-${version}-variables.json \
                                    -var "use_azure_cli_auth=true" \
                                    ${WORKSPACE}/.jenkins/infrastructure/provision/templates/packer/azure_managed_image/packer-${os_type}.json
                            """
                        }
                    }
                }
            }
        }
    }
}

def buildWindowsManagedImage(String os_series, String img_name_suffix, String launch_configuration, String image_id, String image_version) {

    stage("${launch_configuration} Build") {

        def managed_image_name_id = image_id
        def gallery_image_version = image_version
        def vm_rg_name = "build-${managed_image_name_id}-${img_name_suffix}-${BUILD_NUMBER}"
        // Azure VM names must be 15 characters or less
        def vm_name = img_name_suffix.drop(7) + "-${BUILD_NUMBER}"
        def jenkins_rg_name = params.JENKINS_RESOURCE_GROUP
        def jenkins_vnet_name = params.JENKINS_VNET_NAME
        def jenkins_subnet_name = params.JENKINS_SUBNET_NAME
        def azure_image_id = AZURE_IMAGES_MAP[os_series]["image"]

        stage("Azure CLI Login") {
            withCredentials([
                    usernamePassword(credentialsId: SERVICE_PRINCIPAL_CREDENTIALS_ID,
                                        passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                        usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                    string(credentialsId: 'openenclaveci-subscription-id', variable: 'SUBSCRIPTION_ID'),
                    string(credentialsId: 'TenantID', variable: 'TENANT_ID')]) {
                sh '''#!/bin/bash
                    az login --service-principal -u ${SERVICE_PRINCIPAL_ID} -p ${SERVICE_PRINCIPAL_PASSWORD} --tenant ${TENANT_ID}
                    az account set -s ${SUBSCRIPTION_ID}
                '''
            }
        }

        try {

            stage("Create Resource Group") {
                sh """
                    az group create --name ${vm_rg_name} --location ${REGION}
                """
            }

            stage("Provision VM") {
                withCredentials([
                        usernamePassword(credentialsId: JENKINS_USER_CREDS_ID,
                                            usernameVariable: "SSH_USERNAME",
                                            passwordVariable: "SSH_PASSWORD")]) {
                    withEnv([
                            "JENKINS_RG_NAME=${jenkins_rg_name}",
                            "JENKINS_SUBNET_NAME=${jenkins_subnet_name}",
                            "JENKINS_VNET_NAME=${jenkins_vnet_name}",
                            "VM_RG_NAME=${vm_rg_name}",
                            "REGION=${REGION}",
                            "VM_NAME=${vm_name}",
                            "AZURE_IMAGE_ID=${azure_image_id}"]) {
                        sh '''
                            SUBNET_ID=\$(az network vnet subnet show \
                                --resource-group ${JENKINS_RG_NAME} \
                                --name ${JENKINS_SUBNET_NAME} \
                                --vnet-name ${JENKINS_VNET_NAME} --query id -o tsv)
                            az vm create \
                                --resource-group ${VM_RG_NAME} \
                                --location ${REGION} \
                                --name ${VM_NAME} \
                                --size Standard_DC4s_v3 \
                                --os-disk-size-gb 128 \
                                --subnet \$SUBNET_ID \
                                --admin-username ${SSH_USERNAME} \
                                --admin-password ${SSH_PASSWORD} \
                                --image ${AZURE_IMAGE_ID} \
                                --public-ip-address \"\" \
                                --nsg-rule NONE
                        '''
                    }
                }
            }

            stage("Deploy VM") {
                withCredentials([
                        usernamePassword(credentialsId: JENKINS_USER_CREDS_ID,
                                            usernameVariable: "SSH_USERNAME",
                                            passwordVariable: "SSH_PASSWORD")]) {
                    withEnv([
                            "JENKINS_RG_NAME=${jenkins_rg_name}",
                            "JENKINS_SUBNET_NAME=${jenkins_subnet_name}",
                            "JENKINS_VNET_NAME=${jenkins_vnet_name}",
                            "VM_RG_NAME=${vm_rg_name}",
                            "REGION=${REGION}",
                            "VM_NAME=${vm_name}",
                            "AZURE_IMAGE_ID=${azure_image_id}",
                            "LAUNCH_CONFIGURATION=${launch_configuration}"]) {
                        sh '''
                            VM_DETAILS=\$(az vm show --resource-group ${VM_RG_NAME} \
                                                    --name ${VM_NAME} \
                                                    --show-details)

                            az vm run-command invoke \
                                --resource-group ${VM_RG_NAME} \
                                --name ${VM_NAME} \
                                --command-id EnableRemotePS

                            PRIVATE_IP=\$(echo \$VM_DETAILS | jq -r '.privateIps')

                            rm -f ${WORKSPACE}/scripts/ansible/inventory/hosts-${LAUNCH_CONFIGURATION}

                            echo "[windows-agents]" >> ${WORKSPACE}/scripts/ansible/inventory/hosts-${LAUNCH_CONFIGURATION}
                            echo "\$PRIVATE_IP" >> ${WORKSPACE}/scripts/ansible/inventory/hosts-${LAUNCH_CONFIGURATION}

                            echo "ansible_winrm_transport: ntlm" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "launch_configuration: ${LAUNCH_CONFIGURATION}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "ansible_user: ${SSH_USERNAME}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "ansible_password: ${SSH_PASSWORD}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        '''
                    }
                }
                common.exec_with_retry(5, 120) {
                    sh """
                        cd ${WORKSPACE}/scripts/ansible
                        ansible-playbook -i ${WORKSPACE}/scripts/ansible/inventory/hosts-${launch_configuration} oe-windows-acc-setup.yml jenkins-packer.yml

                        az vm run-command invoke \
                            --resource-group ${vm_rg_name} \
                            --name ${vm_name} \
                            --command-id RunPowerShellScript \
                            --scripts @${WORKSPACE}/.jenkins/infrastructure/provision/run-sysprep.ps1
                    """
                }
            }

            stage("Generalize VM") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    common.exec_with_retry(5, 60) {
                        sh """
                            az vm deallocate --resource-group ${vm_rg_name} --name ${vm_name}
                            az vm generalize --resource-group ${vm_rg_name} --name ${vm_name}
                        """
                    }
                }
            }

            stage("Capture Image") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    common.exec_with_retry(5, 60) {
                        sh """
                            VM_ID=\$(az vm show \
                                --resource-group ${vm_rg_name} \
                                --name ${vm_name} | jq -r '.id' )

                            # If the target image doesn't exist, the below command
                            # will not fail because it is idempotent.
                            az image delete \
                                --resource-group ${RESOURCE_GROUP} \
                                --name ${managed_image_name_id}-${img_name_suffix}

                            az image create \
                                --resource-group ${RESOURCE_GROUP} \
                                --name ${managed_image_name_id}-${img_name_suffix} \
                                --hyper-v-generation ${AZURE_IMAGES_MAP[os_series]["generation"]} \
                                --source \$VM_ID
                        """
                    }
                }
            }

            stage("Upload Image") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    common.exec_with_retry(10, 30) {
                        sh """
                            MANAGED_IMG_ID=\$(az image show \
                                --resource-group ${RESOURCE_GROUP} \
                                --name ${managed_image_name_id}-${img_name_suffix} \
                                | jq -r '.id' )

                            # If the target image version doesn't exist, the below
                            # command will not fail because it is idempotent.
                            az sig image-version delete \
                                --resource-group ${RESOURCE_GROUP} \
                                --gallery-name ${GALLERY_NAME} \
                                --gallery-image-definition ${img_name_suffix} \
                                --gallery-image-version ${gallery_image_version}

                            az sig image-version create \
                                --resource-group ${RESOURCE_GROUP} \
                                --gallery-name ${GALLERY_NAME} \
                                --gallery-image-definition ${img_name_suffix} \
                                --gallery-image-version ${gallery_image_version} \
                                --managed-image \$MANAGED_IMG_ID \
                                --target-regions ${env.REPLICATION_REGIONS.split(',').join(' ')} \
                                --replica-count 1
                        """
                    }
                }
            }
        } finally {
            stage("${img_name_suffix}-cleanup") {
                sh """
                    az group delete --name ${vm_rg_name} --yes
                    az image delete \
                        --resource-group ${RESOURCE_GROUP} \
                        --name ${managed_image_name_id}-${img_name_suffix}
                """
            }
        }
    }
}

node(params.AGENTS_LABEL) {
    try {
        stage("Initialize Workspace") {

            cleanWs()
            checkout([$class: 'GitSCM',
                branches: [[name: BRANCH_NAME]],
                extensions: [],
                userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY_NAME}"]]])

            commit_id = helpers.get_commit_id()

            if (params.IMAGE_VERSION) {
                image_version = params.IMAGE_VERSION
            } else {
                image_version = helpers.get_date(".") + "${BUILD_NUMBER}"
            }
            
            image_id = params.IMAGE_ID ?: "${image_version}-${commit_id}"

            println("IMAGE_VERSION: ${image_version}\nIMAGE_ID: ${image_id}")
        }
        stage("Install Azure CLI") {
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
                    sudo apt-get -y install azure-cli jq
                """
            }
        }
        stage("Install Ansible") {
            retry(10) {
                sh """#!/bin/bash
                    ${helpers.WaitForAptLock()}
                    sudo ${WORKSPACE}/scripts/ansible/install-ansible.sh
                """
            }
        }
        stage("Build Agents") {
            parallel "Build Windows Server 2019 - nonSGX"      : { buildWindowsManagedImage("win2019", "ws2019-nonSGX", "SGX1FLC-NoIntelDrivers", image_id, image_version) },
                    "Build Windows Server 2019 - SGX1"         : { buildWindowsManagedImage("win2019", "ws2019-SGX", "SGX1", image_id, image_version) },
                    "Build Windows Server 2019 - SGX1FLC DCAP" : { buildWindowsManagedImage("win2019", "ws2019-SGX-DCAP", "SGX1FLC", image_id, image_version) },
                    "Build Ubuntu 18.04"                       : { buildLinuxManagedImage("ubuntu", "18.04", image_id, image_version) },
                    "Build Ubuntu 20.04"                       : { buildLinuxManagedImage("ubuntu", "20.04", image_id, image_version) }
        }
    } finally {
        stage("Clean up") {
            sh """
                az logout || true
                az cache purge
                az account clear
            """
            cleanWs()
        }
    }
}
