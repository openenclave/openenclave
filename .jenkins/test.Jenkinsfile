// Build Docker images triggering 'OpenEnclave-Docker-Images' job with code from current branch and repository
stage("Build Docker Images") {
    build job: '/CI-CD_Infrastructure/OpenEnclave_build-docker-images' ,
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: env.BUILD_TAG),
                       booleanParam(name: 'TAG_LATEST',value: false)]
}

stage("Build Jenkins Agents images") {
    build job: '/CI-CD_Infrastructure/build-managed-images' ,
          parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.BUILD_TAG}"),
                       string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'IMAGE_ID', value: "e2e")]
}

stage("Run tests on new Agents") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-custom_label-test',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: env.BUILD_TAG),
                       string(name: 'UBUNTU_1604_CUSTOM_LABEL', value: "xenial-e2e"),
                       string(name: 'UBUNTU_1804_CUSTOM_LABEL', value: "bionic-e2e"),
                       string(name: 'WINDOWS_2016_CUSTOM_LABEL', value: "windows-e2e"),
                       string(name: 'WINDOWS_DCAP_CUSTOM_LABEL', value: "windows-dcap-e2e")]
}
