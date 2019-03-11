import hudson.slaves.*
import hudson.model.*

env.XENIAL_RG = "oe-libcxx-${BUILD_NUMBER}-1604"
env.XENIAL_LABEL = "LIBCXX-${BUILD_NUMBER}-1604"
env.XENIAL_HOSTS = "libcxx-${BUILD_NUMBER}-1604-1.eastus.cloudapp.azure.com," + \
                   "libcxx-${BUILD_NUMBER}-1604-2.eastus.cloudapp.azure.com," + \
                   "libcxx-${BUILD_NUMBER}-1604-3.eastus.cloudapp.azure.com"

env.BIONIC_RG = "oe-libcxx-${BUILD_NUMBER}-1804"
env.BIONIC_LABEL = "LIBCXX-${BUILD_NUMBER}-1804"
env.BIONIC_HOSTS = "libcxx-${BUILD_NUMBER}-1804-1.westeurope.cloudapp.azure.com," + \
                   "libcxx-${BUILD_NUMBER}-1804-2.westeurope.cloudapp.azure.com," + \
                   "libcxx-${BUILD_NUMBER}-1804-3.westeurope.cloudapp.azure.com"


String dockerBuildArgs(String... args) {
    String argumentString = ""
    for(arg in args) {
        argumentString += " --build-arg ${arg}"
    }
    return argumentString
}

def azureEnvironment(String task) {
    node("nonSGX") {
        cleanWs()
        checkout scm
        String buildArgs = dockerBuildArgs("UID=\$(id -u)",
                                           "GID=\$(id -g)",
                                           "UNAME=\$(id -un)",
                                           "GNAME=\$(id -gn)")

        def azure_image = docker.build("oetools-deploy", "${buildArgs} -f .jenkins/Dockerfile.deploy .")
        azure_image.inside {
            timeout(60) {
                withCredentials([usernamePassword(credentialsId: 'SERVICE_PRINCIPAL_OSTCLAB',
                                                  passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                                  usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                                 string(credentialsId: 'OSCTLabSubID', variable: 'SUBSCRIPTION_ID'),
                                 string(credentialsId: 'TenantID', variable: 'TENANT_ID')]) {
                    dir('.jenkins/provision') {
                        sh "${task}"
                    }
                }
            }
        }
    }
}

def ACCDeployVM(String agent_name, String agent_type, String region, String resource_group) {
    stage("Deploy ${agent_name}") {
        withEnv(["REGION=${region}", "RESOURCE_GROUP=${resource_group}", "AGENT_NAME=${agent_name}", "AGENT_TYPE=${agent_type}"]) {
            azureEnvironment("./deploy-agent.sh")
        }
    }
}

def registerJenkinsSlaves() {
    stage("Register Jenkins Slaves") {
        withCredentials([usernamePassword(credentialsId: 'oe-ci',
                                          passwordVariable: 'JENKINS_ADMIN_PASSWORD',
                                          usernameVariable: 'JENKINS_ADMIN_NAME'),
                         string(credentialsId: 'JENKINS_PRIVATE_URL',
                                variable: 'JENKINS_PRIVATE_URL')]) {
            withEnv(["JENKINS_URL=${JENKINS_PRIVATE_URL}"]) {
                azureEnvironment("./register-agents.sh")
            }
        }
    }
}

def ACClibcxxTest(String agent_name, String compiler, String build_type) {
    stage("${agent_name} SGX1FLC ${compiler} ${build_type}") {
        node("${agent_name}") {
            cleanWs()
            checkout scm

            timeout(180) {
                def c_compiler = "clang-7"
                def cpp_compiler = "clang++-7"
                if (compiler == "gcc") {
                  c_compiler = "gcc"
                  cpp_compiler = "g++"
                }
                dir('build'){
                    withEnv(["CC=${c_compiler}","CXX=${cpp_compiler}"]) {
                        sh """
                        CMAKE="cmake .. -DCMAKE_BUILD_TYPE=${build_type} -DUSE_LIBSGX=ON -DENABLE_FULL_LIBCXX_TESTS=ON"
                        if ! \${CMAKE}; then
                            echo ""
                            echo "cmake failed for SGX1FLC"
                            echo ""
                            exit 1
                        fi
                        if ! make; then
                            echo ""
                            echo "Build failed for SGX1FLC"
                            echo ""
                            exit 1
                        fi
                        if ! ctest -VV -debug; then
                            echo ""
                            echo "Test failed for SGX1FLC ${build_type} on agent ${agent_name}"
                            echo ""
                            exit 1
                        fi
                        """
                    }
                }
            }
        }
    }
}

def deleteRG() {
    stage("Delete the libcxx resource groups") {
        withEnv(["RESOURCE_GROUP=${env.XENIAL_RG}"]) {
            azureEnvironment("./cleanup.sh")
        }
        withEnv(["RESOURCE_GROUP=${env.BIONIC_RG}"]) {
            azureEnvironment("./cleanup.sh")
        }
    }
}

def unregisterJenkinsSlaves() {
    stage("Unregister Jenkins Slaves") {
        node("nonSGX") {
            for (s in hudson.model.Hudson.instance.slaves) {
                if(s.getLabelString() == "${env.XENIAL_LABEL}" || s.getLabelString() == "${env.BIONIC_LABEL}") {
                    s.getComputer().doDoDelete()
                }
            }
        }
    }
}


try {
    ACCDeployVM("libcxx-${BUILD_NUMBER}-1604-1", "xenial", "eastus", "${env.XENIAL_RG}")
    ACCDeployVM("libcxx-${BUILD_NUMBER}-1604-2", "xenial", "eastus", "${env.XENIAL_RG}")
    ACCDeployVM("libcxx-${BUILD_NUMBER}-1604-3", "xenial", "eastus", "${env.XENIAL_RG}")
    ACCDeployVM("libcxx-${BUILD_NUMBER}-1804-1", "bionic", "westeurope", "${env.BIONIC_RG}")
    ACCDeployVM("libcxx-${BUILD_NUMBER}-1804-2", "bionic", "westeurope", "${env.BIONIC_RG}")
    ACCDeployVM("libcxx-${BUILD_NUMBER}-1804-3", "bionic", "westeurope", "${env.BIONIC_RG}")

    registerJenkinsSlaves()

    parallel "libcxx ACC1604 clang-7 Debug" :          { ACClibcxxTest("${env.XENIAL_LABEL}", 'clang-7', 'Debug') },
             "libcxx ACC1604 clang-7 Release" :        { ACClibcxxTest("${env.XENIAL_LABEL}", 'clang-7','Release') },
             "libcxx ACC1604 clang-7 RelWithDebInfo" : { ACClibcxxTest("${env.XENIAL_LABEL}", 'clang-7', 'RelWithDebinfo') },
             "libcxx ACC1604 gcc Debug" :              { ACClibcxxTest("${env.XENIAL_LABEL}", 'gcc', 'Debug') },
             "libcxx ACC1604 gcc Release" :            { ACClibcxxTest("${env.XENIAL_LABEL}", 'gcc', 'Release') },
             "libcxx ACC1604 gcc RelWithDebInfo" :     { ACClibcxxTest("${env.XENIAL_LABEL}", 'gcc', 'RelWithDebInfo') },
             "libcxx ACC1804 clang-7 Debug" :          { ACClibcxxTest("${env.BIONIC_LABEL}", 'clang-7', 'Debug') },
             "libcxx ACC1804 clang-7 Release" :        { ACClibcxxTest("${env.BIONIC_LABEL}", 'clang-7', 'Release') },
             "libcxx ACC1804 clang-7 RelWithDebInfo" : { ACClibcxxTest("${env.BIONIC_LABEL}", 'clang-7', 'RelWithDebinfo') },
             "libcxx ACC1804 gcc Debug" :              { ACClibcxxTest("${env.BIONIC_LABEL}", 'gcc', 'Debug') },
             "libcxx ACC1804 gcc Release" :            { ACClibcxxTest("${env.BIONIC_LABEL}", 'gcc', 'Release') },
             "libcxx ACC1804 gcc RelWithDebInfo" :     { ACClibcxxTest("${env.BIONIC_LABEL}", 'gcc', 'RelWithDebinfo') }
} finally {
    deleteRG()
    unregisterJenkinsSlaves()
}
