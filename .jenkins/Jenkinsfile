pipeline {
  agent any
  stages {
    stage('Precommit-checking') {
      agent {
        docker {
          image 'oetools-azure:1.0'
        }

      }
      steps {
        echo 'Precommit-checking'
        sh 'bash ./scripts/check-precommit-reqs'
      }
    }
    stage('Build and Test') {
      parallel {
        stage('sgx1-debug Simulation') {
          agent {
            docker {
              image 'oetools-azure:1.0'
            }

          }
          steps {
            echo 'sgx1-debug Simulation'
            sh 'bash ./scripts/test-build-config -b Debug'
          }
        }
        stage('sgx1-release Simulation') {
          agent {
            docker {
              image 'oetools-azure:1.0'
            }

          }
          steps {
            echo 'sgx1-release Simulation'
            sh 'bash ./scripts/test-build-config -p SGX1 -b Release'
          }
        }
        stage('sgx1-relwithdebinfo Simulation') {
          agent {
            docker {
              image 'oetools-azure:1.0'
            }

          }
          steps {
            echo 'sgx1-relwithdebinfo Simulation'
            sh 'bash ./scripts/test-build-config -p SGX1 -b RelWithDebInfo'
          }
        }
        stage('sgx1-flc-debug Simulation') {
          agent {
            docker {
              image 'oetools-azure:1.0'
            }

          }
          steps {
            echo 'sgx1-flc-debug Simulation'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug'
          }
        }
        stage('sgx1-flc-release Simulation') {
          agent {
            docker {
              image 'oetools-azure:1.0'
            }

          }
          steps {
            echo 'sgx1-flc-release Simulation'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release'
          }
        }
        stage('sgx1-flc-relwithdebinfo Simulation') {
          agent {
            docker {
              image 'oetools-azure:1.0'
            }

          }
          steps {
            echo 'sgx1-flc-relwithdebinfo Simulation'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo'
          }
        }
        stage('sgx1-flc ACC VM Coffeelake Hardware Debug') {
          agent {
            node {
              label 'hardware'
            }

          }
          steps {
            echo 'sgx1-flc ACC VM Coffeelake Hardware Debug'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Debug -d'
          }
        }
        stage('sgx1-flc ACC VM Coffeelake Hardware Release') {
          agent {
            node {
              label 'hardware'
            }

          }
          steps {
            echo 'sgx1-flc ACC VM Coffeelake Hardware Release'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b Release -d'
          }
        }
        stage('sgx1-flc ACC VM Coffeelake Hardware RelWithDebInfo') {
          agent {
            node {
              label 'hardware'
            }

          }
          steps {
            echo 'sgx1-flc ACC VM Coffeelake Hardware RelWithDebInfo'
            sh 'bash ./scripts/test-build-config -p SGX1FLC -b RelWithDebInfo -d'
          }
        }
      }
    }
  }
}
