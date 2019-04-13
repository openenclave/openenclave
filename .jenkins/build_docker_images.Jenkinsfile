@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()
OETOOLS_REPO = "https://oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"

def buildDockerImages() {
    node("nonSGX") {
        stage("Checkout") {
            cleanWs()
            checkout scm
        }
        stage("Build Ubuntu1604 Docker Image") {
            oefull1604 = oe.dockerImage("oetools-full-16.04:${DOCKER_TAG}", ".jenkins/Dockerfile.full", "--build-arg ubuntu_version=16.04")
        }
        stage("Build Ubuntu1804 Docker Image") {
            oefull1804 = oe.dockerImage("oetools-full-18.04:${DOCKER_TAG}", ".jenkins/Dockerfile.full", "--build-arg ubuntu_version=18.04")
        }
         stage("Build Ubuntu1604 scripts Docker image") {
            oeminimal1604 = oe.dockerImage("oetools-minimal-16.04:${DOCKER_TAG}", ".jenkins/Dockerfile.minimal", "--build-arg ubuntu_version=16.04")
        }
        stage("Build Ubuntu1804 scripts Docker image") {
            oeminimal1804 = oe.dockerImage("oetools-minimal-18.04:${DOCKER_TAG}", ".jenkins/Dockerfile.minimal", "--build-arg ubuntu_version=18.04")
        }
        stage("Push to OE Docker Registry") {
            docker.withRegistry(OETOOLS_REPO, OETOOLS_REPO_CREDENTIAL_ID) {
                oefull1604.push()
                oefull1804.push()
                oeminimal1604.push()
                oeminimal1804.push()
                oefull1604.push('latest')
                oefull1804.push('latest')
                oeminimal1604.push('latest')
                oeminimal1804.push('latest')
            }
        }
    }
}

buildDockerImages()
