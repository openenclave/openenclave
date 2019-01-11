pipeline {
  agent any
  stages {
    stage('Build, Test, and Package') {
      parallel {
        stage('1604 SGX1FLC Package Debug') {
          agent {
            node {
              label 'ACC-1604'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/1604/Debug/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/1604/Debug/SGX1FLC/', containerName: 'oejenkins')
            }
          }
        }
        stage('1604 SGX1FLC Package Release') {
          agent {
            node {
              label 'ACC-1604'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/1604/Release/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/1604/Release/SGX1FLC/', containerName: 'oejenkins')
              withCredentials([usernamePassword(credentialsId: 'https_gh_pages_push', passwordVariable: 'GHUSER_PASSWORD', usernameVariable: 'GHUSER_ID')]) {
                sh 'bash ./scripts/deploy-docs build https $GHUSER_ID $GHUSER_PASSWORD'
              }
            }
          }
        }
        stage('1604 SGX1FLC Package RelWithDebInfo') {
          agent {
            node {
              label 'ACC-1604'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/1604/RelWithDebInfo/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/1604/RelWithDebInfo/SGX1FLC/', containerName: 'oejenkins')
            }
          }
        }
        stage('1804 SGX1FLC Package Debug') {
          agent {
            node {
              label 'ACC-1804'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/1804/Debug/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/1804/Debug/SGX1FLC/', containerName: 'oejenkins')
            }
          }
        }
        stage('1804 SGX1FLC Package Release') {
          agent {
            node {
              label 'ACC-1804'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/1804/Release/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/1804/Release/SGX1FLC/', containerName: 'oejenkins')
              withCredentials([usernamePassword(credentialsId: 'https_gh_pages_push', passwordVariable: 'GHUSER_PASSWORD', usernameVariable: 'GHUSER_ID')]) {
                sh 'bash ./scripts/deploy-docs build https $GHUSER_ID $GHUSER_PASSWORD'
              }
            }
          }
        }
        stage('1804 SGX1FLC Package RelWithDebInfo') {
          agent {
            node {
              label 'ACC-1804'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/1804/RelWithDebInfo/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/1804/RelWithDebInfo/SGX1FLC/', containerName: 'oejenkins')
            }
          }
        }
        stage('Windows Release') {
          agent {
            node {
              label 'SGXFLC-Windows'
            }
          }

          steps {
            timeout(10) {
              bat '''mkdir build && cd build && cmake -G "Visual Studio 15 2017 Win64" .. && pushd . && "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\BuildTools\\Common7\\Tools\\LaunchDevCmd.bat" && popd && cmake --build . --config Debug && ctest -C Debug'''
              azureUpload(storageCredentialId: 'oedownload_id', filesPath: 'build/output/bin/oeedger8r.exe', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/oeedger8r/', containerName: 'binaries')
            }
          }
        }
      }
    }
  }
}
