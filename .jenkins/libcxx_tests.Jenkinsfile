import hudson.slaves.*
import hudson.model.*

@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

XENIAL_LABEL = "LIBCXX-${BUILD_NUMBER}-1604"
BIONIC_LABEL = "LIBCXX-${BUILD_NUMBER}-1804"
XENIAL_RG = "oe-${XENIAL_LABEL}"
BIONIC_RG = "oe-${BIONIC_LABEL}"

// Number of agents to spawn for each Ubuntu Version
AGENT_NUM = 3

// Function that generates HOSTS variabiles used in registerJenkinsSlaves
String hostsList(String label, String region) {
    def result = []
    for (int i = 1 ; i <= AGENT_NUM ; i++ ) {
        result.add("${label}-${i}.${region}.cloudapp.azure.com".toLowerCase())
    }
    return result
}

def ACCDeployVM(String agent_name, String agent_type, String region, String resource_group, String vhd_url) {
    stage("Deploy ${agent_name}") {
        node("nonSGX") {
            cleanWs()
            checkout scm
            withEnv(["REGION=${region}", "RESOURCE_GROUP=${resource_group}", "AGENT_NAME=${agent_name}", "AGENT_TYPE=${agent_type}", "VHD_URL=${vhd_url}"]) {
                dir("${WORKSPACE}/.jenkins/provision") {
                    oe.azureEnvironment("./deploy-agent.sh")
                }
            }
        }
    }
}

def registerJenkinsSlaves() {
    stage("Register Jenkins Slaves") {
        node("nonSGX") {
            cleanWs()
            checkout scm
            withCredentials([usernamePassword(credentialsId: 'oe-ci',
                                              passwordVariable: 'JENKINS_ADMIN_PASSWORD',
                                              usernameVariable: 'JENKINS_ADMIN_NAME'),
                             string(credentialsId: 'JENKINS_PRIVATE_URL',
                                    variable: 'JENKINS_PRIVATE_URL')]) {
                withEnv(["JENKINS_URL=${JENKINS_PRIVATE_URL}",
                         "XENIAL_LABEL=${XENIAL_LABEL}",
                         "BIONIC_LABEL=${BIONIC_LABEL}",
                         "XENIAL_HOSTS=${hostsList(XENIAL_LABEL, 'eastus').join(',')}",
                         "BIONIC_HOSTS=${hostsList(BIONIC_LABEL, 'westeurope').join(',')}"]) {
                    dir(WORKSPACE) {
                        oe.azureEnvironment("${WORKSPACE}/.jenkins/provision/register-agents.sh")
                    }
                }
            }
        }
    }
}

def unregisterJenkinsSlaves() {
    stage("Unregister Jenkins Slaves") {
        node("nonSGX") {
            for (s in hudson.model.Hudson.instance.slaves) {
                if(s.getLabelString() == XENIAL_LABEL || s.getLabelString() == BIONIC_LABEL) {
                    s.getComputer().doDoDelete()
                }
            }
        }
    }
}

def ACClibcxxTest(String label, String compiler, String build_type) {
    stage("${label} SGX1FLC ${compiler} ${build_type}") {
        node("${label}") {
            cleanWs()
            checkout scm
            def task = """
                       cmake .. -DCMAKE_BUILD_TYPE=${build_type} -DUSE_LIBSGX=ON -DENABLE_FULL_LIBCXX_TESTS=ON
                       make
                       ctest -VV -debug
                       """
            oe.Run(compiler, task, 180)
        }
    }
}

def cleanup(){
    node("nonSGX") {
        cleanWs()
        checkout scm
        oe.deleteRG([XENIAL_RG, BIONIC_RG])
    }
}

try {
    for (int i = 1 ; i <= AGENT_NUM ; i++ ) {
        parallel "Deploy Ubuntu 16.04 #${i}" :  { ACCDeployVM("${XENIAL_LABEL}-${i}".toLowerCase(), "xenial" , "eastus", XENIAL_RG, "${VHD_URL_XENIAL}") },
                 "Deploy Ubuntu 18.04 #${i}" :  { ACCDeployVM("${BIONIC_LABEL}-${i}".toLowerCase(), "bionic", "westeurope", BIONIC_RG, "${VHD_URL_BIONIC}") }
    }

    registerJenkinsSlaves()

    parallel "libcxx ACC1604 clang-8 Debug" :          { ACClibcxxTest(XENIAL_LABEL, 'clang-8', 'Debug') },
             "libcxx ACC1604 clang-8 Release" :        { ACClibcxxTest(XENIAL_LABEL, 'clang-8','Release') },
             "libcxx ACC1604 clang-8 RelWithDebInfo" : { ACClibcxxTest(XENIAL_LABEL, 'clang-8', 'RelWithDebinfo') },
             "libcxx ACC1604 gcc Debug" :              { ACClibcxxTest(XENIAL_LABEL, 'gcc', 'Debug') },
             "libcxx ACC1604 gcc Release" :            { ACClibcxxTest(XENIAL_LABEL, 'gcc', 'Release') },
             "libcxx ACC1604 gcc RelWithDebInfo" :     { ACClibcxxTest(XENIAL_LABEL, 'gcc', 'RelWithDebInfo') },
             "libcxx ACC1804 clang-8 Debug" :          { ACClibcxxTest(BIONIC_LABEL, 'clang-8', 'Debug') },
             "libcxx ACC1804 clang-8 Release" :        { ACClibcxxTest(BIONIC_LABEL, 'clang-8', 'Release') },
             "libcxx ACC1804 clang-8 RelWithDebInfo" : { ACClibcxxTest(BIONIC_LABEL, 'clang-8', 'RelWithDebinfo') },
             "libcxx ACC1804 gcc Debug" :              { ACClibcxxTest(BIONIC_LABEL, 'gcc', 'Debug') },
             "libcxx ACC1804 gcc Release" :            { ACClibcxxTest(BIONIC_LABEL, 'gcc', 'Release') },
             "libcxx ACC1804 gcc RelWithDebInfo" :     { ACClibcxxTest(BIONIC_LABEL, 'gcc', 'RelWithDebinfo') }
} finally {
    cleanup()
    unregisterJenkinsSlaves()
}
