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
    def last_commit_id = sh(script: "git rev-parse --short HEAD", returnStdout: true).tokenize().last()
    return (get_image_version() + "-" + last_commit_id)
}

def buildLinuxManagedImage(String os_type, String version) {
    node(params.AGENTS_LABEL) {
        stage("${os_type}-${version}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def managed_image_name_id = get_image_id()
                def gallery_image_version = get_image_version()
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
                withCredentials([usernamePassword(credentialsId: OETOOLS_REPO_CREDENTIALS_ID,
                                                  usernameVariable: "DOCKER_USER_NAME",
                                                  passwordVariable: "DOCKER_USER_PASSWORD")]) {
                    withEnv(["DOCKER_REGISTRY=${OETOOLS_REPO}",
                             "MANAGED_IMAGE_NAME_ID=${managed_image_name_id}",
                             "GALLERY_IMAGE_VERSION=${gallery_image_version}"]) {
                        def cmd = ("packer build -force " +
                                    "-var-file=${WORKSPACE}/.jenkins/infrastructure/provision/templates/packer/azure_managed_image/${os_type}-${version}-variables.json " +
                                    "${WORKSPACE}/.jenkins/infrastructure/provision/templates/packer/azure_managed_image/packer-${os_type}.json")
                        oe.exec_with_retry(10, 300) {
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
        stage(img_name_suffix) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def managed_image_name_id = get_image_id()
                def gallery_image_version = get_image_version()
                def vm_rg_name = "build-${managed_image_name_id}-${img_name_suffix}-${BUILD_NUMBER}"
                def vm_name = "${os_series}-vm"
                def jenkins_rg_name = params.JENKINS_RESOURCE_GROUP
                def jenkins_vnet_name = params.JENKINS_VNET_NAME
                def jenkins_subnet_name = params.JENKINS_SUBNET_NAME
                def azure_image_id = AZURE_IMAGES_MAP[os_series]["image"]
                withCredentials([usernamePassword(credentialsId: JENKINS_USER_CREDS_ID,
                                                  usernameVariable: "JENKINS_USER_NAME",
                                                  passwordVariable: "JENKINS_USER_PASSWORD")]) {
                    def az_login_script = """
                        az login --service-principal -u \$SERVICE_PRINCIPAL_ID -p \$SERVICE_PRINCIPAL_PASSWORD --tenant \$TENANT_ID
                        az account set -s \$SUBSCRIPTION_ID
                    """
                    def az_build_managed_img_script = """
                        source ${WORKSPACE}/.jenkins/infrastructure/provision/utils.sh

                        ${az_login_script}

                        SUBNET_ID=`az network vnet subnet show \
                            --resource-group ${jenkins_rg_name} \
                            --name ${jenkins_subnet_name} \
                            --vnet-name ${jenkins_vnet_name} --query id -o tsv`

                        VM_ID=`az vm create \
                            --resource-group ${vm_rg_name} \
                            --location ${REGION} \
                            --name ${vm_name} \
                            --size Standard_DC4s \
                            --os-disk-size-gb 128 \
                            --subnet \$SUBNET_ID \
                            --admin-username ${JENKINS_USER_NAME} \
                            --admin-password ${JENKINS_USER_PASSWORD} \
                            --image ${azure_image_id} | jq -r '.id'`

                        VM_DETAILS=`az vm show --ids \$VM_ID --show-details`

                        az vm run-command invoke \
                            --resource-group ${vm_rg_name} \
                            --name ${vm_name} \
                            --command-id EnableRemotePS

                        PRIVATE_IP=`echo \$VM_DETAILS | jq -r '.privateIps'`
                        echo "[windows-agents]" > $WORKSPACE/scripts/ansible/inventory/hosts
                        echo "\$PRIVATE_IP" >> $WORKSPACE/scripts/ansible/inventory/hosts
                        echo "ansible_user: ${JENKINS_USER_NAME}" > $WORKSPACE/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        echo "ansible_password: ${JENKINS_USER_PASSWORD}" >> $WORKSPACE/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        echo "ansible_winrm_transport: ntlm" >> $WORKSPACE/scripts/ansible/inventory/host_vars/\$PRIVATE_IP
                        echo "launch_configuration: ${launch_configuration}" >> $WORKSPACE/scripts/ansible/inventory/host_vars/\$PRIVATE_IP

                        cd $WORKSPACE/scripts/ansible
                        retrycmd_if_failure 5 10 2h ansible-playbook oe-windows-acc-setup.yml
                        retrycmd_if_failure 5 10 30m ansible-playbook jenkins-packer.yml

                        az vm run-command invoke \
                            --resource-group ${vm_rg_name} \
                            --name ${vm_name} \
                            --command-id RunPowerShellScript \
                            --scripts @$WORKSPACE/.jenkins/infrastructure/provision/run-sysprep.ps1

                        az vm deallocate --ids \$VM_ID
                        az vm generalize --ids \$VM_ID

                        # If the target image doesn't exist, the below command
                        # will not fail because it is idempotent.
                        az image delete \
                            --resource-group ${RESOURCE_GROUP} \
                            --name ${managed_image_name_id}-${img_name_suffix}

                        MANAGED_IMG_ID=`az image create \
                            --resource-group ${RESOURCE_GROUP} \
                            --name ${managed_image_name_id}-${img_name_suffix} \
                            --hyper-v-generation ${AZURE_IMAGES_MAP[os_series]["generation"]} \
                            --source \$VM_ID | jq -r '.id'`

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
                    def az_rg_create_script = """
                        ${az_login_script}
                        az group create --name ${vm_rg_name} --location ${REGION}
                    """
                    def az_rg_cleanup_script = """
                        ${az_login_script}
                        az group delete --name ${vm_rg_name} --yes
                    """
                    oe.exec_with_retry(10, 300) {
                        try {
                            oe.azureEnvironment(az_rg_create_script, params.OE_DEPLOY_IMAGE)
                            oe.azureEnvironment(az_build_managed_img_script, params.OE_DEPLOY_IMAGE)
                        } finally {
                            oe.azureEnvironment(az_rg_cleanup_script, params.OE_DEPLOY_IMAGE)
                        }
                    }
                }
            }
        }
    }
}

parallel "Build Ubuntu 16.04"              : { buildLinuxManagedImage("ubuntu", "16.04") },
         "Build Ubuntu 18.04"              : { buildLinuxManagedImage("ubuntu", "18.04") },
         "Build RHEL 8"                    : { buildLinuxManagedImage("rhel", "8") },
         "Build Windows 2016 SGX1"         : { buildWindowsManagedImage("win2016", "ws2016-SGX", "SGX1") },
         "Build Windows 2016 SGX1FLC DCAP" : { buildWindowsManagedImage("win2016", "ws2016-SGX-DCAP", "SGX1FLC") },
         "Build Windows 2016 nonSGX"       : { buildWindowsManagedImage("win2016", "ws2016-nonSGX", "SGX1FLC-NoIntelDrivers") },
         "Build Windows 2019 SGX1"         : { buildWindowsManagedImage("win2019", "ws2019-SGX", "SGX1") },
         "Build Windows 2019 SGX1FLC DCAP" : { buildWindowsManagedImage("win2019", "ws2019-SGX-DCAP", "SGX1FLC") }
