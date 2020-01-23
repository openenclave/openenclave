import hudson.slaves.*
import hudson.model.*

// Get current node label index from CI
def getStartingIndex(String label, String prefix) {
    def startNum = []
    nodesByLabel(label).each {
        startNum.add(it.replace(prefix,"").toInteger())
    }
    return startNum.max() + 1
}

// Generate a list of Agent Names for each Agent Label
def generateAgentNames(String label, String prefix, Integer count) {
    def first = getStartingIndex(label, prefix.toLowerCase())
    def nodeNames = []
    for (int i=0; i<count; ++i) {
        nodeNames.add(prefix + (i + first).toString())
    }
    return nodeNames
}

// Generate a list of Jenkins agent names matching certain labels
def currentAgentList() {
    def agentList = []
    ["ACC-1604", "ACC-1804", "SGXFLC-Windows", "SGXFLC-Windows-DCAP"].each { label ->
        nodesByLabel(label).each {
            agentList.add(it)
        }
    }
    return agentList
}

// Save a list of current Jenkins node names, to be turned offline
CURRENT_JENKINS_NODES = currentAgentList()

def cleanup(List currentNodes) {
    for (aSlave in hudson.model.Hudson.instance.slaves) {
        if (currentNodes.contains(aSlave.name)) {
          println("Set ${aSlave.name} temporarily offline!");
          aSlave.getComputer().setTemporarilyOffline(true,null);
        }
    }
}

// Generate Agent properties map
def xenial = [
    "agentType": "xenial",
    "agentName": generateAgentNames("ACC-1604", "ACC-1604-", 3),
    "agentLabel": "ACC-1604",
    "agentRegion": "eastus",
    "agentVhdUrl": "https://oejenkins.blob.core.windows.net/disks/${env.VHD_NAME_PREFIX}-ubuntu-16.04.vhd"
]

def bionic = [
    "agentType": "bionic",
    "agentName": generateAgentNames("ACC-1804", "ACC-1804-", 3),
    "agentLabel": "ACC-1804",
    "agentRegion": "westeurope",
    "agentVhdUrl": "https://oejenkinswesteurope.blob.core.windows.net/disks/${env.VHD_NAME_PREFIX}-ubuntu-18.04.vhd"
]

def win2016 = [
    "agentType": "windows",
    "agentName": generateAgentNames("SGXFLC-Windows", "ACC-Win-SGX-", 2),
    "agentLabel": "SGXFLC-Windows",
    "agentRegion": "westeurope",
    "agentVhdUrl": "https://oejenkinswesteurope.blob.core.windows.net/disks/${env.VHD_NAME_PREFIX}-win-2016.vhd"
]

def win2016dcap = [
    "agentType": "windows",
    "agentName": generateAgentNames("SGXFLC-Windows-DCAP", "ACC-Win-", 2),
    "agentLabel": "SGXFLC-Windows-DCAP",
    "agentRegion": "westeurope",
    "agentVhdUrl": "https://oejenkinswesteurope.blob.core.windows.net/disks/${env.VHD_NAME_PREFIX}-win-dcap.vhd"
]

def agentsProperties = [
    "xenial": xenial,
    "bionic": bionic,
    "win2016": win2016,
    "win2016dcap": win2016dcap
]



if(BUILD_IMAGES == "true") {
    // Build Docker images triggering 'OpenEnclave-Docker-Images' job with code from OpenEnclave master branch
    stage("Build Docker Images") {
        build job: 'OpenEnclave-Docker-Images' ,
              parameters: [string(name: 'REPOSITORY_NAME', value: "openenclave/openenclave"),
                           string(name: 'BRANCH_SPECIFIER', value: "master"),
                           string(name: 'DOCKER_TAG', value: env.DOCKER_TAG),
                           booleanParam(name: 'TAG_LATEST',value: true)]
    }

    /*
    Build VHD images triggering 'OpenEnclave-jenkins-agents-VHDs' job with code from OpenEnclave master branch
    Here we will use the oe-deploy docker image with the tag we just built in previous job
    */
    stage("Build Jenkins Agents VHDs") {
        build job: 'OpenEnclave-jenkins-agents-VHDs' ,
              parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.DOCKER_TAG}"),
                           string(name: 'REPOSITORY_NAME', value: "openenclave/openenclave"),
                           string(name: 'BRANCH_SPECIFIER', value: "master"),
                           string(name: 'VHD_NAME_PREFIX', value: env.VHD_NAME_PREFIX)]
    }
}

/*
Deploy Jenkins agents with the latest VHD
Register the new Jenkins agents into our CI
*/

def stepsForParallel = [:]
agentsProperties.keySet().each { agent ->
    agentsProperties[agent]['agentName'].each { agent_name ->
        stepsForParallel[agent_name] = {
            build job: 'OpenEnclave-deploy-jenkins-agent-test',
                parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.DOCKER_TAG}"),
                             string(name: 'REPOSITORY_NAME', value: "openenclave/openenclave"),
                             string(name: 'BRANCH_SPECIFIER', value: "master"),
                             string(name: 'VHD_URL', value: agentsProperties[agent]['agentVhdUrl']),
                             string(name: 'REGION', value: agentsProperties[agent]['agentRegion']),
                             string(name: 'RESOURCE_GROUP', value: agent_name),
                             string(name: 'AGENT_NAME', value: agent_name.toLowerCase()),
                             string(name: 'AGENT_LABEL', value: agentsProperties[agent]['agentLabel']),
                             string(name: 'AGENT_TYPE', value: agentsProperties[agent]['agentType'])]
        }
    }
}

// Deploy Jenkins Agents
parallel stepsForParallel

// Mark old Jenkins agents offline
stage("Mark old Jenkins agents offline") {
    cleanup(CURRENT_JENKINS_NODES)  
}
