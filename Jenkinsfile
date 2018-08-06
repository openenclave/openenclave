pipeline {
  agent any
  stages {
    stage('Precommit-checking') {
      agent {
        docker {
          image 'oetools-jenkins:0.1'
        }

      }
      steps {
        echo 'Precommit-checking'
        sh 'bash ./scripts/check-precommit-reqs'
      }
    }
    stage('sgx1-debug') {
      parallel {
        stage('sgx1-debug') {
          agent {
            docker {
              image 'oetools-jenkins:0.1'
            }

          }
          steps {
            echo 'sgx1-debug'
            sh 'bash ./scripts/test-build-config'
          }
        }
        stage('sgx1-release') {
          agent {
            docker {
              image 'oetools-jenkins:0.1'
            }

          }
          steps {
            echo 'sgx1-release'
            sh 'bash ./scripts/test-build-config -p SGX1 -b Release'
          }
        }
        stage('sgx1-relwithdebinfo') {
          agent {
            docker {
              image 'oetools-jenkins:0.1'
            }

          }
          steps {
            echo 'sgx1-relwithdebinfo'
            sh 'bash ./scripts/test-build-config -p SGX1 -b RelWithDebInfo'
          }
        }
        stage('sgx1-flc-debug') {
          agent {
            docker {
              image 'oetools-jenkins:0.1'
            }

          }
          steps {
            echo 'sgx1-flc-debug'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug'
          }
        }
        stage('sgx1-flc-release') {
          agent {
            docker {
              image 'oetools-jenkins:0.1'
            }

          }
          steps {
            echo 'sgx1-flc-release'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release'
          }
        }
        stage('sgx1-flc-relwithdebinfo') {
          agent {
            docker {
              image 'oetools-jenkins:0.1'
            }

          }
          steps {
            echo 'sgx1-flc-relwithdebinfo'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo'
          }
        }
        stage('sgx1-flc on ACC VM with Hardware') {
          agent {
            node {
              label 'hardware'
            }

          }
          steps {
            echo 'sgx1-flc on ACC VM with Hardware'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -d'
          }
        }
      }
    }
  }
}

