@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240

OETOOLS_REPO = "https://oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"
OETOOLS_DOCKERHUB_REPO_CREDENTIAL_ID = "oeciteamdockerhub"

def buildWindowsDockerImages() {
    stage("Windows Docker Images") {
        node('SGXFLC-Windows-DCAP') {
            stage("Checkout") {
                cleanWs()
                checkout scm
            }
            oefullWin2016 = oe.dockerImage("oetools-full-ltsc2016:${DOCKER_TAG}", ".jenkins/Dockerfile.full.WindowsServer", "--build-arg windows_version=ltsc2016")
            puboefullWin2016 = oe.dockerImage("oeciteam/oetools-full-ltsc2016:${DOCKER_TAG}", ".jenkins/Dockerfile.full.WindowsServer", "--build-arg windows_version=ltsc2016")
            docker.withRegistry(OETOOLS_REPO, OETOOLS_REPO_CREDENTIAL_ID) {
              oefullWin2016.push()
              if(TAG_LATEST == "true") {
                oefullWin2016.push('latest')
              }
            }
            docker.withRegistry('', OETOOLS_DOCKERHUB_REPO_CREDENTIAL_ID) {
                if(TAG_LATEST == "true") {
                        puboefullWin2016.push('latest')
                }
            }
        }
    }
}

def buildLinuxDockerImages() {
    stage("nonSGX") {
        node("nonSGX") {
            stage("Checkout") {
                cleanWs()
                checkout scm
            }
            String buildArgs = oe.dockerBuildArgs("UID=\$(id -u)", "UNAME=\$(id -un)",
                                                  "GID=\$(id -g)", "GNAME=\$(id -gn)")
            stage("Build Ubuntu 16.04 Full Docker Image") {
                oefull1604 = oe.dockerImage("oetools-full-16.04:${DOCKER_TAG}", ".jenkins/Dockerfile.full", "${buildArgs} --build-arg ubuntu_version=16.04 --build-arg devkits_uri=${DEVKITS_URI}")
                puboefull1604 = oe.dockerImage("oeciteam/oetools-full-16.04:${DOCKER_TAG}", ".jenkins/Dockerfile.full", "${buildArgs} --build-arg ubuntu_version=16.04 --build-arg devkits_uri=${DEVKITS_URI}")
            }
            stage("Build Ubuntu 18.04 Full Docker Image") {
                oefull1804 = oe.dockerImage("oetools-full-18.04:${DOCKER_TAG}", ".jenkins/Dockerfile.full", "${buildArgs} --build-arg ubuntu_version=18.04 --build-arg devkits_uri=${DEVKITS_URI}")
                puboefull1804 = oe.dockerImage("oeciteam/oetools-full-18.04:${DOCKER_TAG}", ".jenkins/Dockerfile.full", "${buildArgs} --build-arg ubuntu_version=18.04 --build-arg devkits_uri=${DEVKITS_URI}")
            }
            stage("Build Ubuntu 16.04 Minimal Docker image") {
                oeminimal1604 = oe.dockerImage("oetools-minimal-16.04:${DOCKER_TAG}", ".jenkins/Dockerfile.minimal", "${buildArgs} --build-arg ubuntu_version=16.04")
                puboeminimal1604 = oe.dockerImage("oeciteam/oetools-minimal-16.04:${DOCKER_TAG}", ".jenkins/Dockerfile.minimal", "${buildArgs} --build-arg ubuntu_version=16.04")
            }
            stage("Build Ubuntu 18.04 Minimal Docker image") {
                oeminimal1804 = oe.dockerImage("oetools-minimal-18.04:${DOCKER_TAG}", ".jenkins/Dockerfile.minimal", "${buildArgs} --build-arg ubuntu_version=18.04")
                puboeminimal1804 = oe.dockerImage("oeciteam/oetools-minimal-18.04:${DOCKER_TAG}", ".jenkins/Dockerfile.minimal", "${buildArgs} --build-arg ubuntu_version=18.04")
            }
            stage("Build Ubuntu Deploy Docker image") {
                oeDeploy = oe.dockerImage("oetools-deploy:${DOCKER_TAG}", ".jenkins/Dockerfile.deploy", buildArgs)
                puboeDeploy = oe.dockerImage("oeciteam/oetools-deploy:${DOCKER_TAG}", ".jenkins/Dockerfile.deploy", buildArgs)
            }
            stage("Push to OE Docker Registry") {
                docker.withRegistry(OETOOLS_REPO, OETOOLS_REPO_CREDENTIAL_ID) {
                    oefull1604.push()
                    oefull1804.push()
                    oeminimal1604.push()
                    oeminimal1804.push()
                    oeDeploy.push()
                    if(TAG_LATEST == "true") {
                        oefull1604.push('latest')
                        oefull1804.push('latest')
                        oeminimal1604.push('latest')
                        oeminimal1804.push('latest')
                        oeDeploy.push('latest')
                    }
                }
            }
            stage("Push to OE Docker Hub Registry") {
                docker.withRegistry('', OETOOLS_DOCKERHUB_REPO_CREDENTIAL_ID) {
                    if(TAG_LATEST == "true") {
                        puboefull1604.push()
                        puboefull1804.push()
                        puboeminimal1604.push()
                        puboeminimal1804.push()
                        puboeDeploy.push()
                        puboefull1604.push('latest')
                        puboefull1804.push('latest')
                        puboeminimal1604.push('latest')
                        puboeminimal1804.push('latest')
                        puboeDeploy.push('latest')
                    }
            }
        }
    }
}

parallel "Build Linux Docker Images" :    { buildLinuxDockerImages() },
         "Build Windows Docker Images" :  { buildWindowsDockerImages() }
