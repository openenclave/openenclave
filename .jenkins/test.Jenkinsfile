// Build Docker images triggering 'OpenEnclave-Docker-Images' job with code from current branch and repository
stage("Build Docker Images") {
    build job: 'OpenEnclave-Docker-Images' ,
          parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_SPECIFIER', value: env.BRANCH),
                       string(name: 'DOCKER_TAG', value: env.BUILD_TAG),
                       booleanParam(name: 'TAG_LATEST',value: false)]
}

/*
Build VHD images triggering 'OpenEnclave-jenkins-agents-VHDs' job with code from current branch and repository
Here we will use the oe-deploy docker image with the tag we just built in previous job
*/
stage("Build Jenkins Agents VHDs") {
    build job: 'OpenEnclave-jenkins-agents-VHDs' ,
          parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.BUILD_TAG}"),
                       string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                       string(name: 'BRANCH_SPECIFIER', value: env.BRANCH),
                       string(name: 'VHD_NAME_PREFIX', value: env.BUILD_TAG)]
}

try {
  /*
  Deploy Jenkins agents with the custom VHD
  Register the new Jenkins agents into our CI with custom label.
  */
  stage("Deploy and register Jenkins Agent") {
      parallel (
          "Windows" : {
              build job: 'OpenEnclave-deploy-jenkins-agent-test',
                    parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.BUILD_TAG}"),
                                 string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                                 string(name: 'BRANCH_SPECIFIER', value: env.BRANCH),
                                 string(name: 'VHD_URL', value: "https://oejenkinswesteurope.blob.core.windows.net/disks/${env.BUILD_TAG}-win-2016.vhd"),
                                 string(name: 'REGION', value: "westeurope"),
                                 string(name: 'RESOURCE_GROUP', value: "windows-${env.BUILD_TAG}"),
                                 string(name: 'AGENT_NAME', value: "win-2016-${env.BUILD_NUMBER}-1"),
                                 string(name: 'AGENT_LABEL', value: "windows-${env.BUILD_TAG}"),
                                 string(name: 'AGENT_TYPE', value: 'windows')]
          },
          "Windows DCAP" : {
              build job: 'OpenEnclave-deploy-jenkins-agent-test',
                    parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.BUILD_TAG}"),
                                 string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                                 string(name: 'BRANCH_SPECIFIER', value: env.BRANCH),
                                 string(name: 'VHD_URL', value: "https://oejenkinswesteurope.blob.core.windows.net/disks/${env.BUILD_TAG}-win-dcap.vhd"),
                                 string(name: 'REGION', value: "westeurope"),
                                 string(name: 'RESOURCE_GROUP', value: "windows-dcap-${env.BUILD_TAG}"),
                                 string(name: 'AGENT_NAME', value: "win-dcap-${env.BUILD_NUMBER}-1"),
                                 string(name: 'AGENT_LABEL', value: "windows-dcap-${env.BUILD_TAG}"),
                                 string(name: 'AGENT_TYPE', value: 'windows')]
          },
          "Ubuntu 16.04" : {
              build job: 'OpenEnclave-deploy-jenkins-agent-test',
                    parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.BUILD_TAG}"),
                                 string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                                 string(name: 'BRANCH_SPECIFIER', value: env.BRANCH),
                                 string(name: 'VHD_URL', value: "https://oejenkins.blob.core.windows.net/disks/${env.BUILD_TAG}-ubuntu-16.04.vhd"),
                                 string(name: 'REGION', value: "eastus"),
                                 string(name: 'RESOURCE_GROUP', value: "xenial-${env.BUILD_TAG}"),
                                 string(name: 'AGENT_NAME', value: "xenial-${env.BUILD_NUMBER}-1"),
                                 string(name: 'AGENT_LABEL', value: "xenial-${env.BUILD_TAG}"),
                                 string(name: 'AGENT_TYPE', value: 'xenial')]
          },
          "Ubuntu 18.04" : {
              build job: 'OpenEnclave-deploy-jenkins-agent-test',
                    parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.BUILD_TAG}"),
                                 string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                                 string(name: 'BRANCH_SPECIFIER', value: env.BRANCH),
                                 string(name: 'VHD_URL', value: "https://oejenkinswesteurope.blob.core.windows.net/disks/${env.BUILD_TAG}-ubuntu-18.04.vhd"),
                                 string(name: 'REGION', value: "westeurope"),
                                 string(name: 'RESOURCE_GROUP', value: "bionic-${env.BUILD_TAG}"),
                                 string(name: 'AGENT_NAME', value: "bionic-${env.BUILD_NUMBER}-1"),
                                 string(name: 'AGENT_LABEL', value: "bionic-${env.BUILD_TAG}"),
                                 string(name: 'AGENT_TYPE', value: 'bionic')]
          }
      )
  }
  stage("Run tests on new Agents") {
      build job: 'OpenEnclave-custom_label-test',
            parameters: [string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                         string(name: 'BRANCH_SPECIFIER', value: env.BRANCH),
                         string(name: 'DOCKER_TAG', value: env.BUILD_TAG),
                         string(name: 'UBUNTU_1604_CUSTOM_LABEL', value: "xenial-${env.BUILD_TAG}"),
                         string(name: 'UBUNTU_1804_CUSTOM_LABEL', value: "bionic-${env.BUILD_TAG}"),
                         string(name: 'WINDOWS_2016_CUSTOM_LABEL', value: "windows-${env.BUILD_TAG}"),
                         string(name: 'WINDOWS_DCAP_CUSTOM_LABEL', value: "windows-dcap-${env.BUILD_TAG}")]
  }

} finally {
    /*
    Cleanup Azure RG and remove Jenkins Agents from CI
    */
    stage("Cleanup Resource Groups and Jenkins Agents") {
        build job: "OpenEnclave-jenkins-agents-cleanup",
              parameters: [string(name: 'OE_DEPLOY_IMAGE', value: "oetools-deploy:${env.BUILD_TAG}"),
                           string(name: 'REPOSITORY_NAME', value: env.REPOSITORY),
                           string(name: 'BRANCH_SPECIFIER', value: env.BRANCH),
                           string(name: "AGENT_LABELS", value: "xenial-${env.BUILD_TAG},bionic-${env.BUILD_TAG},windows-${env.BUILD_TAG},windows-dcap-${env.BUILD_TAG}"),
                           string(name: "RESOURCE_GROUPS", value: "xenial-${env.BUILD_TAG},bionic-${env.BUILD_TAG},windows-${env.BUILD_TAG},windows-dcap-${env.BUILD_TAG}")]
    }
}
