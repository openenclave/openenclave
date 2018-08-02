pipeline {
  agent {
    docker {
      image 'oetools-jenkins:0.1'
    }

  }
  stages {
    stage('Clone and Setup') {
      steps {
        echo 'Performing pre-commit checking'
        sh '''pwd

ls -l


'''
        sh '''
echo "Merging master to your branch .."

# git pull origin master --no-edit'''
      }
    }
    stage('Precommit-checking') {
      steps {
        echo 'Precommit-checking'
        sh '#./scripts/check-precommit-reqs'
      }
    }
    stage('sgx1-debug') {
      parallel {
        stage('sgx1-debug') {
          steps {
            sh './scripts/test-build-config'
            echo 'sgx1-debug'
          }
        }
        stage('sgx1-release') {
          steps {
            echo 'sgx1-release'
            sh './scripts/test-build-config -p SGX1 -b Release'
          }
        }
        stage('sgx1-relwithdebinfo') {
          steps {
            echo 'sgx1-relwithdebinfo'
            sh './scripts/test-build-config -p SGX1 -b RelWithDebInfo'
          }
        }
        stage('sgx1-flc-debug') {
          steps {
            echo 'sgx1-flc-debug'
            sh './scripts/test-build-config -p SGX1FLC -b Debug'
          }
        }
        stage('sgx1-flc-release') {
          steps {
            echo 'sgx1-flc-release'
            sh './scripts/test-build-config -p SGX1FLC -b Release'
          }
        }
        stage('sgx1-flc-relwithdebinfo') {
          steps {
            echo 'sgx1-flc-relwithdebinfo'
            sh './scripts/test-build-config -p SGX1FLC -b RelWithDebInfo'
          }
        }
      }
    }
  }
}