pipeline {
  agent any
  stages {
    stage('Build and Run libcxx Tests') {
      parallel {
        stage('libcxx clang-7 Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(180) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --enable_full_libcxx_tests --compiler=clang-7'
            }
          }
        }
        stage('libcxx clang-7 Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(180) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --enable_full_libcxx_tests --compiler=clang-7'
            }
          }
        }
        stage('libcxx clang-7 RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(180) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --enable_full_libcxx_tests --compiler=clang-7'
            }
          }
        }
        stage('libcxx gcc Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(180) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --enable_full_libcxx_tests --compiler=gcc'
            }
          }
        }
        stage('libcxx gcc Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(180) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --enable_full_libcxx_tests --compiler=gcc'
            }
          }
        }
        stage('libcxx gcc RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            timeout(180) {
              sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --enable_full_libcxx_tests --compiler=gcc'
            }
          }
        }
      }
    }
  }
}
