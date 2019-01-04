pipeline {
  agent any
  stages {
    stage('Build, Test, and Package') {
      parallel {
        stage('SGX1FLC Package Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/Debug/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/Debug/SGX1FLC/', containerName: 'oejenkins')
            }
          }
        }
        stage('SGX1FLC Package Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/Release/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/Release/SGX1FLC/', containerName: 'oejenkins')
              withCredentials([usernamePassword(credentialsId: 'https_gh_pages_push', passwordVariable: 'GHUSER_PASSWORD', usernameVariable: 'GHUSER_ID')]) {
                sh 'bash ./scripts/deploy-docs build https $GHUSER_ID $GHUSER_PASSWORD'
              }
            }
          }
        }
        stage('SGX1FLC Package RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/RelWithDebInfo/SGX1FLC/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/RelWithDebInfo/SGX1FLC/', containerName: 'oejenkins')
            }
          }
        }
        stage('SGX1 Package Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1 -b Debug --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/Debug/SGX1/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/Debug/SGX1/', containerName: 'oejenkins')
            }
          }
        }
        stage('SGX1 Package Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1 -b Release --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/Release/SGX1/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/Release/SGX1/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oedownload_id', filesPath: 'build/output/bin/oeedger8r', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/oeedger8r/', containerName: 'binaries')
            }
          }
        }
        stage('SGX1 Package RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(10) {
              sh 'bash ./scripts/test-build-config -p SGX1 -b RelWithDebInfo --build_package'
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/${BUILD_NUMBER}/RelWithDebInfo/SGX1/', containerName: 'oejenkins')
              azureUpload(storageCredentialId: 'oejenkinsciartifacts_storageaccount', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: 'master/latest/RelWithDebInfo/SGX1/', containerName: 'oejenkins')
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
