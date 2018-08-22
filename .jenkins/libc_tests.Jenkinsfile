pipeline {
  agent any
  stages {
    stage('Build and Run libc Tests') {
      parallel {
        stage('libc Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --enable_full_libc_tests'
          }
        }
        stage('libc Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --enable_full_libc_tests'
          }
        }
        stage('libc RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --enable_full_libc_tests'
          }
        }
      }
    }
  }
}
