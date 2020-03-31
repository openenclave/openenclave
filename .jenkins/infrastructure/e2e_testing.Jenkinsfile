import java.time.*
import java.time.format.DateTimeFormatter

@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240

OETOOLS_REPO_NAME = "oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"
OETOOLS_DOCKERHUB_REPO_CREDENTIAL_ID = "oeciteamdockerhub"

IMAGE_ID = ""
NOW = LocalDateTime.now()
IMAGE_VERSION = NOW.format(DateTimeFormatter.ofPattern("yyyy")) + "." + \
                NOW.format(DateTimeFormatter.ofPattern("MM")) + "." + \
                NOW.format(DateTimeFormatter.ofPattern("dd"))
DOCKER_TAG = "e2e-${IMAGE_VERSION}-${BUILD_NUMBER}"


node("images-build-e2e") {
    stage("Determine the Azure managed images id") {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            cleanWs()
            checkout scm
            def last_commit_id = sh(script: "git rev-parse --short HEAD", returnStdout: true).tokenize().last()
            IMAGE_ID = IMAGE_VERSION + "-" + last_commit_id
        }
    }
}

stage("Build Docker Images") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Build-Docker-Images',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                       string(name: 'AGENTS_LABEL', value: "images-build-e2e"),
                       booleanParam(name: 'TAG_LATEST',value: false)]
}

stage("Build Jenkins Agents images") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Build-Azure-Managed-Images',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${DOCKER_TAG}"),
                       string(name: 'RESOURCE_GROUP', value: env.RESOURCE_GROUP),
                       string(name: 'GALLERY_NAME', value: env.E2E_IMAGES_GALLERY_NAME),
                       string(name: 'IMAGE_ID', value: IMAGE_ID),
                       string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                       string(name: 'AGENTS_LABEL', value: "images-build-e2e")]
}

stage("Run tests on new Agents") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Testing',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: DOCKER_TAG),
                       string(name: 'UBUNTU_1604_CUSTOM_LABEL', value: "xenial-e2e"),
                       string(name: 'UBUNTU_1804_CUSTOM_LABEL', value: "bionic-e2e"),
                       string(name: 'UBUNTU_NONSGX_CUSTOM_LABEL', value: "nonSGX-e2e"),
                       string(name: 'RHEL_8_CUSTOM_LABEL', value: "rhel-8-e2e"),
                       string(name: 'WINDOWS_2016_CUSTOM_LABEL', value: "windows-e2e"),
                       string(name: 'WINDOWS_2016_DCAP_CUSTOM_LABEL', value: "windows-dcap-e2e"),
                       string(name: 'WINDOWS_NONSGX_CUSTOM_LABEL', value: "nonSGX-Windows-e2e")]
}

if(params.UPDATE_PRODUCTION_INFRA) {
    def docker_images_names = ["oetools-full-16.04",
                               "oetools-full-18.04",
                               "oetools-minimal-18.04",
                               "oetools-deploy"]

    node("nonSGX") {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            stage("Backup current production Docker images") {
                docker.withRegistry("https://${OETOOLS_REPO_NAME}", OETOOLS_REPO_CREDENTIAL_ID) {
                    for (image_name in docker_images_names) {
                        def image = docker.image("${OETOOLS_REPO_NAME}/${image_name}:latest")
                        oe.exec_with_retry { image.pull() }
                        oe.exec_with_retry { image.push("latest-backup") }
                    }
                }
            }
        }
    }

    node("nonSGX-e2e") {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            stage("Update production Docker images") {
                docker.withRegistry("https://${OETOOLS_REPO_NAME}", OETOOLS_REPO_CREDENTIAL_ID) {
                    for (image_name in docker_images_names) {
                        def image = docker.image("${OETOOLS_REPO_NAME}/${image_name}:${DOCKER_TAG}")
                        oe.exec_with_retry { image.pull() }
                        oe.exec_with_retry { image.push("latest") }
                    }
                }
            }

            stage("Update production Azure managed images") {
                // Mapping between shared gallery image definition name and
                // generated Azure managed image name
                def azure_images_map = [
                    "ubuntu-16.04":    "${IMAGE_ID}-ubuntu-16.04-SGX",
                    "ubuntu-18.04":    "${IMAGE_ID}-ubuntu-18.04-SGX",
                    "rhel-8":          "${IMAGE_ID}-rhel-8-SGX",
                    "ws2016-nonSGX":   "${IMAGE_ID}-ws2016-nonSGX",
                    "ws2016-SGX":      "${IMAGE_ID}-ws2016-SGX",
                    "ws2016-SGX-DCAP": "${IMAGE_ID}-ws2016-SGX-DCAP"
                ]
                for (image_name in azure_images_map.keySet()) {
                    oe.azureEnvironment("""
                        az login --service-principal -u \$SERVICE_PRINCIPAL_ID -p \$SERVICE_PRINCIPAL_PASSWORD --tenant \$TENANT_ID --output table
                        az account set --subscription \$SUBSCRIPTION_ID --output table

                        MANAGED_IMG_ID=`az image show \
                            --resource-group ${env.RESOURCE_GROUP} \
                            --name ${azure_images_map[image_name]} | jq -r '.id'`

                        az sig image-version delete \
                            --resource-group ${env.RESOURCE_GROUP} \
                            --gallery-name ${env.PRODUCTION_IMAGES_GALLERY_NAME} \
                            --gallery-image-definition ${image_name} \
                            --gallery-image-version ${IMAGE_VERSION}

                        az sig image-version create \
                            --resource-group ${env.RESOURCE_GROUP} \
                            --gallery-name ${env.PRODUCTION_IMAGES_GALLERY_NAME} \
                            --gallery-image-definition ${image_name} \
                            --gallery-image-version ${IMAGE_VERSION} \
                            --managed-image \$MANAGED_IMG_ID \
                            --target-regions "WestEurope" \
                            --replica-count 1
                    """)
                }
            }
        }
    }
}
