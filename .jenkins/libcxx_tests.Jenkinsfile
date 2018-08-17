pipeline {
  agent any
  stages {
    stage('Build and Run libcxx Tests') {
      parallel {
        stage('libcxx') {
          agent {
            node {
              label 'hardware'
          }

          }
          steps {
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d --enable_libcxx_tests'
          }
        }
      }
    }
  }
}
