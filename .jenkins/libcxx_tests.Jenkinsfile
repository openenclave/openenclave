pipeline {
  agent any
  stages {
    stage('Build and Run libcxx Tests') {
      parallel {
        stage('libcxx Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --enable_full_libcxx_tests'
          }
        }
        stage('libcxx Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --enable_full_libcxx_tests'
          }
        }
        stage('libcxx RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --enable_full_libcxx_tests'
          }
        }
      }
    }
  }
}
