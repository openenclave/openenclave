// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

import java.time.*
import java.time.format.DateTimeFormatter

OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

GLOBAL_TIMEOUT_MINUTES = 480

JENKINS_USER_CREDS_ID = "oeadmin-credentials"
OETOOLS_REPO = "oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIALS_ID = "oejenkinscidockerregistry"
AZURE_IMAGES_MAP = [
    "win2016": [
        "image": "MicrosoftWindowsServer:WindowsServer:2016-datacenter-gensecond:latest",
        "generation": "V2"
    ],
    "win2019": [
        "image": "MicrosoftWindowsServer:WindowsServer:2019-datacenter-gensecond:latest",
        "generation": "V2"
    ]
]

def get_image_version() {
    def now = LocalDateTime.now()
    return (now.format(DateTimeFormatter.ofPattern("yyyy")) + "." + \
            now.format(DateTimeFormatter.ofPattern("MM")) + "." + \
            now.format(DateTimeFormatter.ofPattern("dd")))
}

def get_image_id() {
    if (params.IMAGE_ID) {
        return params.IMAGE_ID
    }
    checkout scm
    def last_commit_id = sh(script: "git rev-parse --short HEAD", returnStdout: true).tokenize().last()
    return (get_image_version() + "-" + last_commit_id)
}



def buildLinuxManagedImage(String os_type, String version) {
    node(params.AGENTS_LABEL) {
        def managed_image_name_id = get_image_id()
        def gallery_image_version = get_image_version()
        withEnv(["DOCKER_REGISTRY=${OETOOLS_REPO}",
            "MANAGED_IMAGE_NAME_ID=${managed_image_name_id}",
            "GALLERY_IMAGE_VERSION=${gallery_image_version}"]) {
            stage("${os_type}-${version}-cleanup") {
                def az_cleanup_existing_image_version_script = """
                    az login --service-principal -u \$SERVICE_PRINCIPAL_ID -p \$SERVICE_PRINCIPAL_PASSWORD --tenant \$TENANT_ID
                    az account set -s \$SUBSCRIPTION_ID

                    # If the target image version doesn't exist, the below
                    # command will not fail because it is idempotent.
                    az sig image-version delete \
                        --resource-group ${RESOURCE_GROUP} \
                        --gallery-name ${GALLERY_NAME} \
                        --gallery-image-definition ${os_type}-${version} \
                        --gallery-image-version ${gallery_image_version}
                """
                oe.azureEnvironment(az_cleanup_existing_image_version_script, params.OE_DEPLOY_IMAGE)
            }
            stage("${os_type}-${version}-build") {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    withCredentials([usernamePassword(credentialsId: OETOOLS_REPO_CREDENTIALS_ID,
                                                    usernameVariable: "DOCKER_USER_NAME",
                                                    passwordVariable: "DOCKER_USER_PASSWORD"),
                                    usernamePassword(credentialsId: JENKINS_USER_CREDS_ID,
                                                    usernameVariable: "SSH_USERNAME",
                                                    passwordVariable: "SSH_PASSWORD")]) {
                        def cmd = ("packer build -force " +
                                    "-var-file=${WORKSPACE}/.jenkins/infrastructure/provision/templates/packer/azure_managed_image/${os_type}-${version}-variables.json " +
                                    "${WORKSPACE}/.jenkins/infrastructure/provision/templates/packer/azure_managed_image/packer-${os_type}.json")
                        oe.exec_with_retry(10, 60) {
                            oe.azureEnvironment(cmd, params.OE_DEPLOY_IMAGE)
                        }
                    }
                }
            }
        }
    }
}

def buildWindowsManagedImage(String os_series, String img_name_suffix, String launch_configuration) {
    node(params.AGENTS_LABEL) {
        withCredentials([usernamePassword(credentialsId: JENKINS_USER_CREDS_ID,
                                    usernameVariable: "JENKINS_USER_NAME",
                                    passwordVariable: "JENKINS_USER_PASSWORD")]) {
            def az_login_script = """
                az login --service-principal -u \$SERVICE_PRINCIPAL_ID -p \$SERVICE_PRINCIPAL_PASSWORD --tenant \$TENANT_ID
                az account set -s \$SUBSCRIPTION_ID
            """
            def managed_image_name_id = get_image_id()
            def gallery_image_version = get_image_version()
            def vm_rg_name = "build-${managed_image_name_id}-${img_name_suffix}-${BUILD_NUMBER}"
            def vm_name = "${os_series}-vm"
            def jenkins_rg_name = params.JENKINS_RESOURCE_GROUP
            def jenkins_vnet_name = params.JENKINS_VNET_NAME
            def jenkins_subnet_name = params.JENKINS_SUBNET_NAME
            def azure_image_id = AZURE_IMAGES_MAP[os_series]["image"]

            stage("${img_name_suffix}-prepare") {
                def az_rg_create_script = """
                    ${az_login_script}
                    az group create --name ${vm_rg_name} --location ${REGION}
                """
                cleanWs()
                oe.azureEnvironment(az_rg_create_script, params.OE_DEPLOY_IMAGE)
            }

            try {
                stage("${img_name_suffix}-provisioning") {
                    def provision_script = """
                        ${az_login_script}

                        SUBNET_ID=\$(az network vnet subnet show \
                            --resource-group ${jenkins_rg_name} \
                            --name ${jenkins_subnet_name} \
                            --vnet-name ${jenkins_vnet_name} --query id -o tsv)

                        az vm create \
                            --resource-group ${vm_rg_name} \
                            --location ${REGION} \
                            --name ${vm_name} \
                            --size Standard_DC4s \
                            --os-disk-size-gb 128 \
                            --subnet \$SUBNET_ID \
                            --admin-username ${JENKINS_USER_NAME} \
                            --admin-password ${JENKINS_USER_PASSWORD} \
                            --image ${azure_image_id}
                    """
                    oe.azureEnvironment(provision_script, params.OE_DEPLOY_IMAGE)
                }

                stage("${img_name_suffix}-deploy") {
                    def deploy_script = """
                        ${az_login_script}

                        VM_DETAILS=\$(az vm show --resource-group ${vm_rg_name} \
                                                --name ${vm_name} \
                                                --show-details)

                        az vm run-command invoke \
                            --resource-group ${vm_rg_name} \
                            --name ${vm_name} \
                            --command-id EnableRemotePS
                        
                        PRIVATE_IP=\$(echo \$VM_DETAILS | jq -r '.privateIps')
                        rm -f ${WORKSPACE}/scripts/ansible/inventory/hosts
                        echo "[windows-agents]" >> ${WORKSPACE}/scripts/ansible/inventory/hosts
                        echo "\$PRIVATE_IP" >> ${WORKSPACE}/scripts/ansible/inventory/hosts
                        echo "ansible_user: ${JENKINS_USER_NAME}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        echo "ansible_password: ${JENKINS_USER_PASSWORD}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        echo "ansible_winrm_transport: ntlm" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        echo "launch_configuration: ${launch_configuration}" >> ${WORKSPACE}/scripts/ansible/inventory/host_vars/\$PRIVATE_IP

                        cd ${WORKSPACE}/scripts/ansible
                        source ${WORKSPACE}/.jenkins/infrastructure/provision/utils.sh
                        ansible-playbook oe-windows-acc-setup.yml
                        ansible-playbook jenkins-packer.yml

                        az vm run-command invoke \
                            --resource-group ${vm_rg_name} \
                            --name ${vm_name} \
                            --command-id RunPowerShellScript \
                            --scripts @${WORKSPACE}/.jenkins/infrastructure/provision/run-sysprep.ps1
                    """
                    cleanWs()
                    checkout scm
                    oe.exec_with_retry(10, 30) {
                        oe.azureEnvironment(deploy_script, params.OE_DEPLOY_IMAGE)
                    }
                }


                stage("${img_name_suffix}-generalize") {
                    timeout(GLOBAL_TIMEOUT_MINUTES) {
                        def generalize_script = """
                            ${az_login_script}

                            az vm deallocate --resource-group ${vm_rg_name} --name ${vm_name}
                            az vm generalize --resource-group ${vm_rg_name} --name ${vm_name}
                        """
                        oe.exec_with_retry(10, 30) {                           
                            oe.azureEnvironment(generalize_script, params.OE_DEPLOY_IMAGE)
                        }
                    }
                }

                stage("${img_name_suffix}-capture") {
                    timeout(GLOBAL_TIMEOUT_MINUTES) {
                        def capture_script = """
                            ${az_login_script}

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
                        oe.exec_with_retry(10, 30) {
                            oe.azureEnvironment(capture_script, params.OE_DEPLOY_IMAGE)
                        }
                    }
                }

                stage("${img_name_suffix}-upload") {
                    timeout(GLOBAL_TIMEOUT_MINUTES) {
                        def upload_script = """
                            ${az_login_script}

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
                        oe.exec_with_retry(10, 30) {                           
                            oe.azureEnvironment(upload_script, params.OE_DEPLOY_IMAGE)
                        }
                    }
                }

            } finally {
                stage("${img_name_suffix}-cleanup") {
                    def az_rg_cleanup_script = """
                        ${az_login_script}
                        az group delete --name ${vm_rg_name} --yes
                    """
                    oe.azureEnvironment(az_rg_cleanup_script, params.OE_DEPLOY_IMAGE)
                }
            }
        }
    }
}

parallel "Build Ubuntu 18.04"              : { buildLinuxManagedImage("ubuntu", "18.04") },
         "Build RHEL 8"                    : { buildLinuxManagedImage("rhel", "8") },
         "Build Windows 2016 SGX1"         : { buildWindowsManagedImage("win2016", "ws2016-SGX", "SGX1") },
         "Build Windows 2016 SGX1FLC DCAP" : { buildWindowsManagedImage("win2016", "ws2016-SGX-DCAP", "SGX1FLC") },
         "Build Windows 2016 nonSGX"       : { buildWindowsManagedImage("win2016", "ws2016-nonSGX", "SGX1FLC-NoIntelDrivers") },
         "Build Windows 2019 SGX1"         : { buildWindowsManagedImage("win2019", "ws2019-SGX", "SGX1") },
         "Build Windows 2019 SGX1FLC DCAP" : { buildWindowsManagedImage("win2019", "ws2019-SGX-DCAP", "SGX1FLC") }
