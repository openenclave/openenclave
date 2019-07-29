import hudson.slaves.*
import hudson.model.*

@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 30

def cleanup(List resourceGroups){
    node("nonSGX") {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
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
