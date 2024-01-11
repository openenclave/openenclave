// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

GLOBAL_TIMEOUT_MINUTES = 480

JENKINS_USER_CREDS_ID = 'oeadmin-credentials'
OETOOLS_REPO = 'oejenkinscidockerregistry.azurecr.io'
OETOOLS_REPO_CREDENTIALS_ID = 'oejenkinscidockerregistry'
SERVICE_PRINCIPAL_CREDENTIALS_ID = 'SERVICE_PRINCIPAL_OSTCLAB'
AZURE_IMAGES_MAP = [
    "WS19": [
        "image": "MicrosoftWindowsServer:WindowsServer:2019-datacenter-gensecond:latest",
        "generation": "V2"
    ],
    "WS22": [
        "image": "MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest",
        "generation": "V2"
    ]
]
OS_NAME_MAP = [
    "WS19": "Windows Server 2019",
    "WS22": "Windows Server 2022",
    "ubuntu":  "Ubuntu",
]

def buildLinuxManagedImage(String os_type, String version, String managed_image_name_id, String gallery_image_version) {
    stage('Install prerequisites') {
        retry(10) {
            sh """#!/bin/bash
                sleep 5
                curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
                sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com \$(lsb_release -cs) main"
                ${helpers.WaitForAptLock()}
                sudo apt-get update && sudo apt-get install packer
                packer plugins install github.com/hashicorp/azure
                packer plugins install github.com/hashicorp/ansible
            """
        }
    }
    stage("${OS_NAME_MAP[os_type]} ${version} Build") {
        withEnv([
                "DOCKER_REGISTRY=${OETOOLS_REPO}",
                "MANAGED_IMAGE_NAME_ID=${managed_image_name_id}",
                "GALLERY_IMAGE_VERSION=${gallery_image_version}",
                "RESOURCE_GROUP=${params.RESOURCE_GROUP}",
                "GALLERY_NAME=${params.GALLERY_NAME}",
                "OS_TYPE=${os_type}",
                "OS_VERSION=${version}"]) {
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
                            sh '''#!/bin/bash
                                packer build -force \
                                    -var-file=${WORKSPACE}/.jenkins/infrastructure/provision/templates/packer/azure_managed_image/${OS_TYPE}-${OS_VERSION}-variables.json \
                                    -var "use_azure_cli_auth=true" \
                                    ${WORKSPACE}/.jenkins/infrastructure/provision/templates/packer/azure_managed_image/packer-${OS_TYPE}.json
                            '''
                        }
                    }
                }
            }
        }
    }
}

/* This builds a Windows image for Azure Managed Images
 * @param os_series            String for windows OS version that forms part of the image definition in Azure Compute Galleries.
 *                             Options: "WS19", "WS22"
 * @param image_type           String for image type that forms part of the image definition in Azure Compute Galleries.
 *                             Options: "nonSGX", "SGX-DCAP"
 * @param launch_configuration String for the configuration used to provision the Windows image for the install-windows-prereqs.ps1 script. 
 *                             Options: "SGX1FLC-NoIntelDrivers", "SGX1FLC"
 * @param clang_version        String for the clang version.
 *                             Options: "11.1.0", "10.0.0"
 * @param image_id
 * @param image_version
 */
 
def buildWindowsManagedImage(String os_series, String image_type, String launch_configuration, String clang_version, String image_id, String image_version) {

    stage("${launch_configuration} Build") {

        def managed_image_name_id = image_id
        def gallery_image_version = image_version
        def gallery_image_definition
        def vm_rg_name = "build-${managed_image_name_id}-${os_series}-${image_type}-${clang_version}-${BUILD_NUMBER}"
        def clang_version_short = clang_version.take(2)
        def os_series_short = os_series[-2..-1]
        def image_type_short = image_type.take(3)
        // Azure VM names must be 15 characters or less, cannot start with a number
        def vm_name = image_type_short + os_series_short + "-" + clang_version_short + "-" + BUILD_NUMBER
        def jenkins_rg_name = params.JENKINS_RESOURCE_GROUP
        def jenkins_vnet_name = params.JENKINS_VNET_NAME
        def jenkins_subnet_name = params.JENKINS_SUBNET_NAME
        def azure_image_id = AZURE_IMAGES_MAP[os_series]["image"]

        if (os_series == "WS19") {
            gallery_image_definition = "${image_type}-clang-${clang_version_short}"
        } else if (os_series == "WS22") {
            gallery_image_definition = "${os_series}-${image_type}-clang-${clang_version_short}"
        } else {
            throw new Exception("Only Windows 2019 and 2022 are supported")
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
                        // Create a VM that will be captured as a managed image
                        // Note: Creation of managed images are not supported for virtual machine with TrustedLaunch security type.

                        sh '''
                            SUBNET_ID=\$(az network vnet subnet show \
                                --resource-group ${JENKINS_RG_NAME} \
                                --name ${JENKINS_SUBNET_NAME} \
                                --vnet-name ${JENKINS_VNET_NAME} --query id -o tsv)
                            az vm create \
                                --resource-group ${VM_RG_NAME} \
                                --location ${REGION} \
                                --name ${VM_NAME} \
                                --size Standard_DC2s_v2 \
                                --os-disk-size-gb 128 \
                                --subnet \$SUBNET_ID \
                                --admin-username ${SSH_USERNAME} \
                                --admin-password ${SSH_PASSWORD} \
                                --image ${AZURE_IMAGE_ID} \
                                --public-ip-address \"\" \
                                --nsg-rule NONE \
                                --security-type Standard
                            '''
                        sh """
                            az vm run-command invoke \
                                --resource-group ${VM_RG_NAME} \
                                --name ${VM_NAME} \
                                --command-id EnableRemotePS
                        """
                    }
                }
            }
            
            stage("Setup remote access") {
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

                            PRIVATE_IP=\$(echo \$VM_DETAILS | jq -r '.privateIps')

                            rm -f ${WORKSPACE}/scripts/ansible/inventory/host-${VM_NAME}

                            echo "[windows-agents]" >> ${WORKSPACE}/scripts/ansible/inventory/hosts-${VM_NAME}
                            echo "\$PRIVATE_IP" >> ${WORKSPACE}/scripts/ansible/inventory/hosts-${VM_NAME}
                            echo "ansible_connection: winrm" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "ansible_winrm_transport: ntlm" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "launch_configuration: ${LAUNCH_CONFIGURATION}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "ansible_user: ${SSH_USERNAME}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "ansible_password: ${SSH_PASSWORD}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        '''
                    }
                }
                sh """
                    cd ${WORKSPACE}/scripts/ansible
                    ansible windows-agents \
                        -i ${WORKSPACE}/scripts/ansible/inventory/hosts-${vm_name} \
                        -m ansible.builtin.wait_for_connection \
                        -a "sleep=10 timeout=600"
                """
            }

            stage("Deploy VM") {
                common.exec_with_retry(5, 60) {
                    sh """
                        cd ${WORKSPACE}/scripts/ansible
                        ansible-playbook \
                            -i ${WORKSPACE}/scripts/ansible/inventory/hosts-${vm_name} \
                            --extra-vars \"clang_target_version=${clang_version_short}\" \
                            --extra-vars \"is_azure_vm=yes\" \
                            oe-windows-acc-setup.yml \
                            jenkins-packer.yml

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
                                --name ${managed_image_name_id}-${image_type}-${clang_version}

                            az image create \
                                --resource-group ${RESOURCE_GROUP} \
                                --name ${managed_image_name_id}-${image_type}-${clang_version} \
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
                                --name ${managed_image_name_id}-${image_type}-${clang_version} \
                                | jq -r '.id' )

                            # If the target image version doesn't exist, the below
                            # command will not fail because it is idempotent.
                            az sig image-version delete \
                                --resource-group ${RESOURCE_GROUP} \
                                --gallery-name ${GALLERY_NAME} \
                                --gallery-image-definition ${gallery_image_definition} \
                                --gallery-image-version ${gallery_image_version}

                            az sig image-version create \
                                --resource-group ${RESOURCE_GROUP} \
                                --gallery-name ${GALLERY_NAME} \
                                --gallery-image-definition ${gallery_image_definition} \
                                --gallery-image-version ${gallery_image_version} \
                                --managed-image \$MANAGED_IMG_ID \
                                --target-regions ${env.REPLICATION_REGIONS.split(',').join(' ')} \
                                --replica-count 1
                        """
                    }
                }
            }
        } finally {
            stage("${image_type}-cleanup") {
                sh """
                    az group delete --name ${vm_rg_name} --yes
                    az image delete \
                        --resource-group ${RESOURCE_GROUP} \
                        --name ${managed_image_name_id}-${image_type}-${clang_version}
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
        stage("Azure CLI Login") {
            withCredentials([
                    usernamePassword(credentialsId: SERVICE_PRINCIPAL_CREDENTIALS_ID,
                                     passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                     usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                    string(credentialsId: 'openenclaveci-subscription-id', variable: 'SUBSCRIPTION_ID'),
                    string(credentialsId: 'TenantID', variable: 'TENANT_ID')]) {
                retry(5) {
                    sh '''#!/bin/bash
                        az login --service-principal -u ${SERVICE_PRINCIPAL_ID} -p ${SERVICE_PRINCIPAL_PASSWORD} --tenant ${TENANT_ID}
                        az account set -s ${SUBSCRIPTION_ID}
                    '''
                }
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
        stage("Build images") {
            def windows_images = [
                "Build WS2019 - nonSGX - clang11"       : { buildWindowsManagedImage("WS19", "nonSGX", "SGX1FLC-NoIntelDrivers", "11.1.0", image_id, image_version) },
                "Build WS2019 - SGX1FLC DCAP - clang11" : { buildWindowsManagedImage("WS19", "SGX-DCAP", "SGX1FLC", "11.1.0", image_id, image_version) },
                "Build WS2022 - nonSGX - clang11"       : { buildWindowsManagedImage("WS22", "nonSGX", "SGX1FLC-NoIntelDrivers", "11.1.0", image_id, image_version) },
                "Build WS2022 - SGX1FLC DCAP - clang11" : { buildWindowsManagedImage("WS22", "SGX-DCAP", "SGX1FLC", "11.1.0", image_id, image_version) }
            ]
            def linux_images = [
                "Build Ubuntu 20.04" : { buildLinuxManagedImage("ubuntu", "20.04", image_id, image_version) }
            ]
            def images = [:]
            if (params.BUILD_WINDOWS_IMAGES) {
                images += windows_images
            }
            if (params.BUILD_LINUX_IMAGES) {
                images += linux_images
            }
            parallel images
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
