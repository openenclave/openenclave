pipeline {
  agent any
  stages {
    stage('Build and Run libc Tests') {
      parallel {
        stage('libc clang-7 Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(15) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --enable_full_libc_tests --compiler=clang-7'
            }
          }
        }
        stage('libc clang-7 Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(15) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --enable_full_libc_tests --compiler=clang-7'
            }
          }
        }
        stage('libc clang-7 RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(15) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --enable_full_libc_tests --compiler=clang-7'
            }
          }
        }
        stage('libc gcc Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(15) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --enable_full_libc_tests --compiler=gcc'
            }
          }
        }
        stage('libc gcc Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(15) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --enable_full_libc_tests --compiler=gcc'
            }
          }
        }
        stage('libc gcc RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(15) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --enable_full_libc_tests --compiler=gcc'
            }
          }
        }
      }
    }
  }
}
