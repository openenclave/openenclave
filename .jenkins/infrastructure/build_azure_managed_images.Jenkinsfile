// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

library "OpenEnclaveJenkinsLibrary@${params.OECI_LIB_VERSION}"

GLOBAL_TIMEOUT_MINUTES = 480

JENKINS_USER_CREDS_ID = 'oeadmin-credentials'
JENKINS_SSH_CREDS_ID = 'jenkins-agent-ssh-key'
CONTAINER_REPO = 'openenclave.azurecr.io'
AZURE_IMAGES_MAP = [
    "WS22": [
        "image": "MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest",
        "generation": "V2"
    ],
    "ubuntu": [
        "20.04": [
            "image": "canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest",
            "gallery_image_definition": "ubuntu-20.04",
            "vm_size": "Standard_DC2s_v3",
            "generation": "V2"
        ],
        "22.04": [
            "image": "canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest",
            "gallery_image_definition": "ubuntu-22.04",
            "vm_size": "Standard_DC2s_v3",
            "generation": "V2"
        ]
    ]
]
OS_NAME_MAP = [
    "WS22": "Windows Server 2022",
    "ubuntu":  "Ubuntu",
]

def buildLinuxManagedImage(String os_series, String version, String gallery_image_version) {

    stage("${OS_NAME_MAP[os_series]} ${version} Build") {

        def gallery_image_definition
        def vm_rg_name = "build-${gallery_image_version}-${os_series}-${version}-${BUILD_NUMBER}"
        def os_series_short = os_series[-2..-1]
        // Azure VM names must be 15 characters or less, cannot start with a number
        def vm_name = os_series_short + version.replace('.', '') + "-" + BUILD_NUMBER
        def jenkins_rg_name = params.JENKINS_RESOURCE_GROUP
        def jenkins_vnet_name = params.JENKINS_VNET_NAME
        def jenkins_subnet_name = params.JENKINS_SUBNET_NAME
        def azure_image_id = AZURE_IMAGES_MAP[os_series][version]["image"]

        if (AZURE_IMAGES_MAP[os_series]?.get(version)) {
            gallery_image_definition = AZURE_IMAGES_MAP[os_series][version]["gallery_image_definition"]
        } else {
            throw new Exception("Unsupported Linux image mapping for ${os_series} ${version}")
        }

        try {

            stage("Create Resource Group") {
                sh """
                    az group create --name ${vm_rg_name} --location ${REGION}
                """
            }

            // TVM is not supported for image creation so we must continue to use standard.
            stage("Provision VM") {
                withCredentials([
                        sshUserPrivateKey(credentialsId: JENKINS_SSH_CREDS_ID,
                                         keyFileVariable: 'SSH_KEY_FILE',
                                         usernameVariable: 'SSH_USERNAME')]) {
                    withEnv([
                            "JENKINS_RG_NAME=${jenkins_rg_name}",
                            "JENKINS_SUBNET_NAME=${jenkins_subnet_name}",
                            "JENKINS_VNET_NAME=${jenkins_vnet_name}",
                            "VM_RG_NAME=${vm_rg_name}",
                            "REGION=${REGION}",
                            "VM_NAME=${vm_name}",
                            "AZURE_IMAGE_ID=${azure_image_id}",
                            "VM_SIZE=${AZURE_IMAGES_MAP[os_series][version]["vm_size"]}"]) {
                        // Create a VM that will be captured as a managed image
                        // Note: Creation of managed images are not supported for virtual machine with TrustedLaunch security type.

                        sh '''
                            SUBNET_ID=\$(az network vnet subnet show \
                                --resource-group ${JENKINS_RG_NAME} \
                                --name ${JENKINS_SUBNET_NAME} \
                                --vnet-name ${JENKINS_VNET_NAME} --query id -o tsv)
                            SSH_PUB_KEY=\$(ssh-keygen -y -f ${SSH_KEY_FILE})
                            az vm create \
                                --resource-group ${VM_RG_NAME} \
                                --location ${REGION} \
                                --name ${VM_NAME} \
                                --size ${VM_SIZE} \
                                --os-disk-size-gb 128 \
                                --subnet \$SUBNET_ID \
                                --admin-username ${SSH_USERNAME} \
                                --ssh-key-values "\$SSH_PUB_KEY" \
                                --image ${AZURE_IMAGE_ID} \
                                --public-ip-address \"\" \
                                --nsg-rule NONE \
                                --security-type Standard
                            '''
                    }
                }
            }

            stage("Setup remote access") {
                withCredentials([
                    sshUserPrivateKey(credentialsId: JENKINS_SSH_CREDS_ID,
                                     keyFileVariable: 'SSH_KEY_FILE',
                                     usernameVariable: 'SSH_USERNAME')]) {
                    withEnv([
                            "JENKINS_RG_NAME=${jenkins_rg_name}",
                            "JENKINS_SUBNET_NAME=${jenkins_subnet_name}",
                            "JENKINS_VNET_NAME=${jenkins_vnet_name}",
                            "VM_RG_NAME=${vm_rg_name}",
                            "REGION=${REGION}",
                            "VM_NAME=${vm_name}",
                            "AZURE_IMAGE_ID=${azure_image_id}"]) {
                        sh '''
                            VM_DETAILS=\$(az vm show --resource-group ${VM_RG_NAME} \
                                                     --name ${VM_NAME} \
                                                     --show-details)

                            PRIVATE_IP=\$(echo \$VM_DETAILS | jq -r '.privateIps')

                            rm -f ${WORKSPACE}/scripts/ansible/inventory/hosts-${VM_NAME}
                            mkdir -p ${WORKSPACE}/.ssh
                            cp ${SSH_KEY_FILE} ${WORKSPACE}/.ssh/id_rsa_${VM_NAME}
                            chmod 600 ${WORKSPACE}/.ssh/id_rsa_${VM_NAME}

                            echo "[linux-agents]" >> ${WORKSPACE}/scripts/ansible/inventory/hosts-${VM_NAME}
                            echo "\$PRIVATE_IP" >> ${WORKSPACE}/scripts/ansible/inventory/hosts-${VM_NAME}
                            echo "ansible_ssh_user: ${SSH_USERNAME}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "ansible_ssh_private_key_file: ${WORKSPACE}/.ssh/id_rsa_${VM_NAME}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                            echo "ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=30 -o ServerAliveCountMax=10 -o TCPKeepAlive=yes'" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        '''
                    }
                }
                sh """
                    ANSIBLE_HOST_KEY_CHECKING=False \
                    ansible linux-agents \
                        -i ${WORKSPACE}/scripts/ansible/inventory/hosts-${vm_name} \
                        -m ansible.builtin.wait_for_connection \
                        -a "sleep=10 timeout=600"
                """
            }

            stage("Deploy VM") {
                def docker_extra_vars = ""
                if (params.DOCKER_REGISTRY) {
                    docker_extra_vars += " --extra-vars docker_registry=${params.DOCKER_REGISTRY}"
                }
                if (params.DOCKER_TAG) {
                    docker_extra_vars += " --extra-vars docker_tag=${params.DOCKER_TAG}"
                }
                withCredentials([
                        sshUserPrivateKey(credentialsId: JENKINS_SSH_CREDS_ID,
                                         keyFileVariable: 'SSH_KEY_FILE',
                                         usernameVariable: 'SSH_USERNAME')]) {
                    withEnv(["VM_NAME=${vm_name}",
                             "DOCKER_EXTRA_VARS=${docker_extra_vars}"]) {
                        common.exec_with_retry(5, 60) {
                            timeout(60) {
                                sh '''
                                    cd ${WORKSPACE}/scripts/ansible
                                    ANSIBLE_HOST_KEY_CHECKING=False \
                                    ansible-playbook \
                                        -i ${WORKSPACE}/scripts/ansible/inventory/hosts-${VM_NAME} \
                                        --extra-vars "jenkins_admin_name=${SSH_USERNAME}" \
                                        ${DOCKER_EXTRA_VARS} \
                                        oe-linux-acc-setup.yml \
                                        jenkins-setup.yml
                                '''
                            }
                        }
                    }
                }
            }

            stage("Generalize VM") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    sh """
                        export ANSIBLE_HOST_KEY_CHECKING=False
                        ansible linux-agents \
                            -i ${WORKSPACE}/scripts/ansible/inventory/hosts-${vm_name} \
                            -m ansible.builtin.wait_for_connection \
                            -a "sleep=10 timeout=600"
                        ansible linux-agents \
                            -i ${WORKSPACE}/scripts/ansible/inventory/hosts-${vm_name} \
                            -m ansible.builtin.raw \
                            -a 'sudo waagent -force -deprovision+user && export HISTSIZE=0 && sync'
                    """
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
                                --name ${gallery_image_version}-${os_series}-${version}

                            az image create \
                                --resource-group ${RESOURCE_GROUP} \
                                --name ${gallery_image_version}-${os_series}-${version} \
                                --hyper-v-generation ${AZURE_IMAGES_MAP[os_series][version]["generation"]} \
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
                                --name ${gallery_image_version}-${os_series}-${version} \
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
            stage("${version}-cleanup") {
                sh """
                    rm -f ${WORKSPACE}/.ssh/id_rsa_${vm_name}
                    az group delete --name ${vm_rg_name} --yes
                    az image delete \
                        --resource-group ${RESOURCE_GROUP} \
                        --name ${gallery_image_version}-${os_series}-${version}
                """
            }
        }
    }
}



/* This builds a Windows image for Azure Managed Images
 * @param os_series            String for windows OS version that forms part of the image definition in Azure Compute Galleries.
 *                             Options: "WS22"
 * @param image_type           String for image type that forms part of the image definition in Azure Compute Galleries.
 *                             Options: "nonSGX", "SGX-DCAP"
 * @param launch_configuration String for the configuration used to provision the Windows image for the install-windows-prereqs.ps1 script. 
 *                             Options: "SGX1FLC-NoIntelDrivers", "SGX1FLC"
 * @param clang_version        String for the clang version.
 *                             Options: "11.1.0", "10.0.0"          
 * @param image_version
 */
 
def buildWindowsManagedImage(String os_series, String image_type, String launch_configuration, String clang_version, String gallery_image_version) {

    stage("${launch_configuration} Build") {

        def gallery_image_definition
        def vm_rg_name = "build-${gallery_image_version}-${os_series}-${image_type}-${clang_version}-${BUILD_NUMBER}"
        def clang_version_short = clang_version.take(2)
        def os_series_short = os_series[-2..-1]
        def image_type_short = image_type.take(3)
        // Azure VM names must be 15 characters or less, cannot start with a number
        def vm_name = image_type_short + os_series_short + "-" + clang_version_short + "-" + BUILD_NUMBER
        def jenkins_rg_name = params.JENKINS_RESOURCE_GROUP
        def jenkins_vnet_name = params.JENKINS_VNET_NAME
        def jenkins_subnet_name = params.JENKINS_SUBNET_NAME
        def azure_image_id = AZURE_IMAGES_MAP[os_series]["image"]

        if (os_series == "WS22") {
            gallery_image_definition = "${os_series}-${image_type}-clang-${clang_version_short}"
        } else {
            throw new Exception("Only Windows 2022 is supported")
        }

        try {

            stage("Create Resource Group") {
                sh """
                    az group create --name ${vm_rg_name} --location ${REGION}
                """
            }

            // TVM is not supported for image creation so we must continue to use standard.
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
                            --extra-vars \"ci_team_email=oeciteam@microsoft.com" \
                            --extra-vars \"ci_team_name=OE CI Team\" \
                            oe-windows-acc-setup.yml \
                            jenkins-setup.yml

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
                                --name ${gallery_image_version}-${image_type}-${clang_version}

                            az image create \
                                --resource-group ${RESOURCE_GROUP} \
                                --name ${gallery_image_version}-${image_type}-${clang_version} \
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
                                --name ${gallery_image_version}-${image_type}-${clang_version} \
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
                        --name ${gallery_image_version}-${image_type}-${clang_version}
                """
            }
        }
    }
}

node(params.AGENTS_LABEL) {
    timestamps {
        try {
            stage("Initialize Workspace") {

                cleanWs()
                checkout([$class: 'GitSCM',
                    branches: [[name: BRANCH_NAME]],
                    extensions: [],
                    userRemoteConfigs: [[url: "https://github.com/${params.REPOSITORY_NAME}"]]])

                if (params.IMAGE_VERSION) {
                    image_version = params.IMAGE_VERSION
                } else {
                    image_version = helpers.get_date(".") + "${BUILD_NUMBER}"
                }

                println("IMAGE_VERSION: ${image_version}")
            }
            stage("Install Azure CLI") {
                common.installAzureCLI()
            }
            stage("Azure CLI Login") {
                withCredentials([
                        string(credentialsId: 'Jenkins-CI-Subscription-Id', variable: 'SUBSCRIPTION_ID'),
                        string(credentialsId: 'Jenkins-CI-Tenant-Id', variable: 'TENANT_ID')]) {
                    retry(5) {
                        sh '''#!/bin/bash
                            az login --identity
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
                    "Build WS2022 - nonSGX - clang11"       : { buildWindowsManagedImage("WS22", "nonSGX", "SGX1FLC-NoIntelDrivers", "11.1.0", image_version) },
                    "Build WS2022 - SGX1FLC DCAP - clang11" : { buildWindowsManagedImage("WS22", "SGX-DCAP", "SGX1FLC", "11.1.0", image_version) }
                ]
                def linux_images = [
                    "Build Ubuntu 20.04" : { buildLinuxManagedImage("ubuntu", "20.04", image_version) },
                    "Build Ubuntu 22.04" : { buildLinuxManagedImage("ubuntu", "22.04", image_version) }
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
}
