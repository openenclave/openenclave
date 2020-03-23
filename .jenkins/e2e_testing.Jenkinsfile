// Build Docker images triggering 'OpenEnclave-Docker-Images' job with code from current branch and repository
stage("Build Docker Images") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Build-Docker-Images',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: "e2e"),
                       string(name: 'AGENTS_LABEL', value: "images-build-e2e"),
                       booleanParam(name: 'TAG_LATEST',value: false)]
}

stage("Build Jenkins Agents images") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Build-Azure-Managed-Images',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:e2e"),
                       string(name: 'IMAGE_ID', value: "e2e"),
                       string(name: 'DOCKER_TAG', value: "e2e"),
                       string(name: 'AGENTS_LABEL', value: "images-build-e2e")]
}

stage("Run tests on new Agents") {
    build job: '/CI-CD_Infrastructure/OpenEnclave-Custom-Label-Testing',
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_NAME', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: "e2e"),
                       string(name: 'UBUNTU_1604_CUSTOM_LABEL', value: "xenial-e2e"),
                       string(name: 'UBUNTU_1804_CUSTOM_LABEL', value: "bionic-e2e"),
                       string(name: 'UBUNTU_NONSGX_CUSTOM_LABEL', value: "nonSGX-e2e"),
                       string(name: 'RHEL_8_CUSTOM_LABEL', value: "rhel-8-e2e"),
                       string(name: 'WINDOWS_2016_CUSTOM_LABEL', value: "windows-e2e"),
                       string(name: 'WINDOWS_2016_DCAP_CUSTOM_LABEL', value: "windows-dcap-e2e"),
                       string(name: 'WINDOWS_NONSGX_CUSTOM_LABEL', value: "nonSGX-Windows-e2e")]
}
