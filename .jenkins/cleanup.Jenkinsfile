import hudson.slaves.*
import hudson.model.*

@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

// The below timeout is set in minutes
GLOBAL_TIMEOUT = 30

def cleanup(List resourceGroups){
    node("nonSGX") {
        timeout(GLOBAL_TIMEOUT) {
            cleanWs()
            checkout scm
            oe.deleteRG(resourceGroups, OE_DEPLOY_IMAGE)
        }
    }
}

def unregisterJenkinsSlaves(List jenkinsLabels) {
    stage("Unregister Jenkins Slaves") {
        node("nonSGX") {
            for (s in hudson.model.Hudson.instance.slaves) {
                if(jenkinsLabels.contains(s.getLabelString())) {
                    s.getComputer().doDoDelete()
                }
            }
        }
    }
}

cleanup(RESOURCE_GROUPS.tokenize(","))
unregisterJenkinsSlaves(AGENT_LABELS.tokenize(","))
