@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240

def ACCDeployVM() {
    stage("Deploy ${AGENT_NAME}") {
        node("nonSGX") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                dir("${WORKSPACE}/.jenkins/provision") {
                    oe.azureEnvironment("./deploy-agent.sh", OE_DEPLOY_IMAGE)
                }
            }
        }
    }
}

def generateInventory() {
    if (agent_type == "windows") {
        sh """
           echo "[windows-agents]" > inventory/hosts
           echo ${AGENT_NAME.toLowerCase()}.${REGION}.cloudapp.azure.com >> inventory/hosts
           """
    } else {
        sh """
           echo "[linux-agents]" > inventory/hosts
           echo ${AGENT_NAME.toLowerCase()}.${REGION}.cloudapp.azure.com >> inventory/hosts
           """
    }
}

def generateVariablesFile() {
    def var_file = "inventory/host_vars/${AGENT_NAME.toLowerCase()}.${REGION}.cloudapp.azure.com"
    if (agent_type == "windows") {
      sh """{
         echo jenkins_agent_name: ${AGENT_NAME}
         echo jenkins_agent_label: ${AGENT_LABEL}
         echo jenkins_url: ${JENKINS_PRIVATE_URL}
         echo jenkins_admin_name: ${JENKINS_ADMIN_NAME}
         echo jenkins_admin_password: ${JENKINS_ADMIN_PASSWORD}
         echo ansible_user: ${WINDOWS_ADMIN_USERNAME}
         echo ansible_password: "${WINDOWS_ADMIN_PASSWORD}"
         echo ansible_become_pass: "${WINDOWS_ADMIN_PASSWORD}"
         } > ${var_file} """
    } else {
      sh """
         {
         echo jenkins_agent_name: ${AGENT_NAME}
         echo jenkins_agent_label: ${AGENT_LABEL}
         echo jenkins_url: ${JENKINS_PRIVATE_URL}
         echo jenkins_admin_name: ${JENKINS_ADMIN_NAME}
         echo jenkins_admin_password: ${JENKINS_ADMIN_PASSWORD}
         echo ansible_ssh_private_key_file: inventory/id-rsa-oe-test
         } > ${var_file} """
    }
}

def registerJenkinsSlave() {
    stage("Register Jenkins Slave") {
        node("nonSGX") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                withCredentials([usernamePassword(credentialsId: 'oe-ci',
                                                  passwordVariable: 'JENKINS_ADMIN_PASSWORD',
                                                  usernameVariable: 'JENKINS_ADMIN_NAME'),
                                 usernamePassword(credentialsId: 'acc-vm-windows-azureuser',
                                                  passwordVariable: 'WINDOWS_ADMIN_PASSWORD',
                                                  usernameVariable: 'WINDOWS_ADMIN_USERNAME'),
                                 string(credentialsId: 'JENKINS_PRIVATE_URL',
                                        variable: 'JENKINS_PRIVATE_URL')]) {
                    withEnv(["ANSIBLE_HOST_KEY_CHECKING=False"]) {
                        dir("scripts/ansible") {
                            generateInventory()
                            generateVariablesFile()
                            if (agent_type != "windows") {
                                /*
                                Writing private key data to inventory/id-rsa-oe-test
                                Here we need to use single quotes so Jenkins doesn't interpret variables.
                                SERVICE_PRINCIPAL variables are set into environment by oe.azureEnvironment function
                                */
                                def task = '''
                                  az login --service-principal -u "${SERVICE_PRINCIPAL_ID}" -p "${SERVICE_PRINCIPAL_PASSWORD}" --tenant "${TENANT_ID}" --output table
                                  az account set --subscription "${SUBSCRIPTION_ID}"
                                  az keyvault secret show --vault-name 'oe-ci-test-kv' --name 'id-rsa-oe-test' | jq -r .value | base64 -d > inventory/id-rsa-oe-test
                                  chmod 600 inventory/id-rsa-oe-test
                                  '''
                                oe.azureEnvironment(task , OE_DEPLOY_IMAGE)
                            }
                            oe.azureEnvironment("ansible-playbook jenkins-agents-register.yml", OE_DEPLOY_IMAGE )
                        }
                    }
                }
            }
        }
    }
}

def cleanup() {
    node("nonSGX") {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            cleanWs()
            checkout scm
            oe.deleteRG([RESOURCE_GROUP])
        }
    }
}

try {
    ACCDeployVM()
    registerJenkinsSlave()
} catch (e) {
    println(e)
    cleanup()
    throw e
}
