@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240

JENKINS_USER_CREDS_ID = "oeadmin-credentials"
OETOOLS_REPO = "oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIALS_ID = "oejenkinscidockerregistry"
AZURE_IMAGES_MAP = [
    "win2016": "MicrosoftWindowsServer:confidential-compute-preview:acc-windows-server-2016-datacenter:latest",
]


def buildLinuxManagedImage(String os_type, String version) {
    node(params.AGENTS_LABEL) {
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
                def managed_image_name_id
                if (params.IMAGE_ID) {
                    managed_image_name_id = params.IMAGE_ID
                } else {
                    managed_image_name_id = sh(script: "git rev-parse --short HEAD", returnStdout: true).tokenize().last()
                }
                def rg_name = "build-${managed_image_name_id}-${img_name_suffix}-${BUILD_NUMBER}"
                def azure_image_id = AZURE_IMAGES_MAP[os_series]
                withCredentials([usernamePassword(credentialsId: JENKINS_USER_CREDS_ID,
                                                  usernameVariable: "JENKINS_USER_NAME",
                                                  passwordVariable: "JENKINS_USER_PASSWORD")]) {
                    def az_login_script = """
                        az login --service-principal -u \$SERVICE_PRINCIPAL_ID -p \$SERVICE_PRINCIPAL_PASSWORD --tenant \$TENANT_ID
                        az account set -s \$SUBSCRIPTION_ID
                    """
                    def az_build_managed_img_script = """
                        function retrycmd_if_failure() {
                            set +o errexit
                            retries=\$1; wait_sleep=\$2; timeout=\$3; shift && shift && shift
                            for i in \$(seq 1 \$retries); do
                                timeout \$timeout \${@}
                                [ \$? -eq 0 ] && break || \
                                if [ \$i -eq \$retries ]; then
                                    echo "Error: Failed to execute '\$@' after \$i attempts"
                                    set -o errexit
                                    return 1
                                else
                                    sleep \$wait_sleep
                                fi
                            done
                            echo "Executed '\$@' \$i times"
                            set -o errexit
                        }

                        ${az_login_script}

                        VM_ID=`az vm create \
                            --resource-group ${rg_name} \
                            --location ${REGION} \
                            --name ${img_name_suffix} \
                            --size Standard_DC4s \
                            --os-disk-size-gb 128 \
                            --admin-username ${JENKINS_USER_NAME} \
                            --admin-password ${JENKINS_USER_PASSWORD} \
                            --image ${azure_image_id} | jq -r '.id'`

                        VM_DETAILS=`az vm show --ids \$VM_ID --show-details`

                        NIC_ID=`echo \$VM_DETAILS | jq -r '.networkProfile.networkInterfaces[0].id'`
                        NSG_ID=`az network nic show --ids \$NIC_ID | jq -r '.networkSecurityGroup.id'`
                        NSG_NAME=`az network nsg show --ids \$NSG_ID | jq -r '.name'`
                        az network nsg rule create \
                            --resource-group ${rg_name} \
                            --nsg-name \$NSG_NAME \
                            --name WinRM --priority 500 \
                            --access Allow --direction Inbound --protocol Tcp \
                            --source-address-prefixes Internet \
                            --destination-port-ranges 5986
                        az vm run-command invoke \
                            --resource-group ${rg_name} \
                            --name ${img_name_suffix} \
                            --command-id EnableRemotePS

                        PUBLIC_IP=`echo \$VM_DETAILS | jq -r '.publicIps'`
                        echo "[windows-agents]" > $WORKSPACE/scripts/ansible/inventory/hosts
                        echo "\$PUBLIC_IP" >> $WORKSPACE/scripts/ansible/inventory/hosts
                        echo "ansible_user: ${JENKINS_USER_NAME}" > $WORKSPACE/scripts/ansible/inventory/host_vars/\$PUBLIC_IP
                        echo "ansible_password: ${JENKINS_USER_PASSWORD}" >> $WORKSPACE/scripts/ansible/inventory/host_vars/\$PUBLIC_IP
                        echo "ansible_winrm_transport: ntlm" >> $WORKSPACE/scripts/ansible/inventory/host_vars/\$PUBLIC_IP
                        echo "launch_configuration: ${launch_configuration}" >> $WORKSPACE/scripts/ansible/inventory/host_vars/\$PUBLIC_IP

                        cd $WORKSPACE/scripts/ansible
                        retrycmd_if_failure 5 10 2h ansible-playbook oe-windows-acc-setup.yml
                        retrycmd_if_failure 5 10 30m ansible-playbook jenkins-packer.yml

                        az vm run-command invoke \
                            --resource-group ${rg_name} \
                            --name ${img_name_suffix} \
                            --command-id RunPowerShellScript \
                            --scripts @$WORKSPACE/.jenkins/provision/run-sysprep.ps1

                        az vm deallocate --ids \$VM_ID
                        az vm generalize --ids \$VM_ID
                        MANAGED_IMG_ID=`az image create \
                            --resource-group ${rg_name} \
                            --name ${managed_image_name_id}-${img_name_suffix} \
                            --source ${img_name_suffix} | jq -r '.id'`

                        # If the target image doesn't exist, the below command
                        # will not fail because it is idempotent.
                        retrycmd_if_failure 10 300 30m az image delete \
                            --resource-group ${RESOURCE_GROUP} \
                            --name ${managed_image_name_id}-${img_name_suffix}

                        retrycmd_if_failure 10 300 30m az resource move \
                            --ids \$MANAGED_IMG_ID \
                            --destination-group ${RESOURCE_GROUP}
                    """
                    def az_rg_create_script = """
                        ${az_login_script}
                        az group create --name ${rg_name} --location ${REGION}
                    """
                    def az_rg_cleanup_script = """
                        ${az_login_script}
                        az group delete --name ${rg_name} --yes
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
         "Build Windows 2016 nonSGX"       : { buildWindowsManagedImage("win2016", "ws2016-nonSGX", "SGX1FLC-NoDriver") }
