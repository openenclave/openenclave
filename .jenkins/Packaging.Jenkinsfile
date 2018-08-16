pipeline {
  agent any
  stages {
    stage('Build, Test, and Package') {
      parallel {
        stage('SGX1FLC Package') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --build_package'
            azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: '${BUILD_NUMBER}/SGX1FLC/', containerName: 'oejenkins')
          }
        }
        stage('SGX1 Package') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1 -b Debug --build_package'
            azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: '${BUILD_NUMBER}/SGX1/', containerName: 'oejenkins')
          }
        }
      }
    }
  }
}
