// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

OECI_LIB_VERSION = env.OECI_LIB_VERSION ?: "master"
oe = library("OpenEnclaveCommon@${OECI_LIB_VERSION}").jenkins.common.Openenclave.new()

GLOBAL_TIMEOUT_MINUTES = 240

OETOOLS_REPO_NAME = "oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"

DOCKER_IMAGES_NAMES = ["oetools-full-16.04", "oetools-full-18.04", "oetools-minimal-18.04", "oetools-deploy"]
AZURE_IMAGES_MAP = [
    // Mapping between shared gallery image definition name and
    // generated Azure managed image name
    "ubuntu-16.04":    "${env.IMAGE_ID}-ubuntu-16.04-SGX",
    "ubuntu-18.04":    "${env.IMAGE_ID}-ubuntu-18.04-SGX",
    "rhel-8":          "${env.IMAGE_ID}-rhel-8-SGX",
    "ws2016-nonSGX":   "${env.IMAGE_ID}-ws2016-nonSGX",
    "ws2016-SGX":      "${env.IMAGE_ID}-ws2016-SGX",
    "ws2016-SGX-DCAP": "${env.IMAGE_ID}-ws2016-SGX-DCAP",
    "ws2019-SGX":      "${env.IMAGE_ID}-ws2019-SGX",
    "ws2019-SGX-DCAP": "${env.IMAGE_ID}-ws2019-SGX-DCAP"
]
IMAGES_BUILD_LABEL = env.IMAGES_BUILD_LABEL ?: "nonSGX"


def update_production_docker_images() {
    node("nonSGX") {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            stage("Backup current production Docker images") {
                docker.withRegistry("https://${OETOOLS_REPO_NAME}", OETOOLS_REPO_CREDENTIAL_ID) {
                    for (image_name in DOCKER_IMAGES_NAMES) {
                        def image = docker.image("${OETOOLS_REPO_NAME}/${image_name}:latest")
                        oe.exec_with_retry { image.pull() }
                        oe.exec_with_retry { image.push("latest-backup") }
                    }
                }
            }
        }
    }
    node(IMAGES_BUILD_LABEL) {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            stage("Update production Docker images") {
                docker.withRegistry("https://${OETOOLS_REPO_NAME}", OETOOLS_REPO_CREDENTIAL_ID) {
                    for (image_name in DOCKER_IMAGES_NAMES) {
                        def image = docker.image("${OETOOLS_REPO_NAME}/${image_name}:${env.DOCKER_TAG}")
                        oe.exec_with_retry { image.pull() }
                        oe.exec_with_retry { image.push("latest") }
                    }
                }
            }
        }
    }
}

def update_production_azure_gallery_images(String image_name) {
    node(IMAGES_BUILD_LABEL) {
        timeout(GLOBAL_TIMEOUT_MINUTES) {
            stage("Update production Azure managed image: ${image_name}") {
                def az_update_image_script = """
                    az login --service-principal -u \$SERVICE_PRINCIPAL_ID -p \$SERVICE_PRINCIPAL_PASSWORD --tenant \$TENANT_ID --output table
                    az account set --subscription \$SUBSCRIPTION_ID --output table

                    MANAGED_IMG_ID=`az image show \
                        --resource-group ${env.RESOURCE_GROUP} \
                        --name ${AZURE_IMAGES_MAP[image_name]} | jq -r '.id'`

                    az sig image-version delete \
                        --resource-group ${env.RESOURCE_GROUP} \
                        --gallery-name ${env.PRODUCTION_IMAGES_GALLERY_NAME} \
                        --gallery-image-definition ${image_name} \
                        --gallery-image-version ${env.IMAGE_VERSION}

                    az sig image-version create \
                        --resource-group ${env.RESOURCE_GROUP} \
                        --gallery-name ${env.PRODUCTION_IMAGES_GALLERY_NAME} \
                        --gallery-image-definition ${image_name} \
                        --gallery-image-version ${env.IMAGE_VERSION} \
                        --managed-image \$MANAGED_IMG_ID \
                        --target-regions ${env.REPLICATION_REGIONS.split(',').join(' ')} \
                        --replica-count 1
                """
                oe.azureEnvironment(az_update_image_script, "oetools-deploy:${env.DOCKER_TAG}")
            }
        }
    }
}

def parallel_steps = [ "Update Docker images": { update_production_docker_images() } ]
AZURE_IMAGES_MAP.keySet().each { image_name ->
  parallel_steps["Update Azure gallery ${image_name} image"] = { update_production_azure_gallery_images(image_name) }
}

parallel parallel_steps
