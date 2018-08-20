pipeline {
  agent any
  stages {
    stage('Build and Run libcxx Tests') {
      parallel {
        stage('libcxx and libc Debug') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --enable_full_libcxx_tests --enable_full_libc_tests'
          }
        }
        stage('libcxx and libc Release') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d --enable_full_libcxx_tests --enable_full_libc_tests'
          }
        }
        stage('libcxx and libc RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d --enable_full_libcxx_tests --enable_full_libc_tests'
          }
        }
      }
    }
  }
}
