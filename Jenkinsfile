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
    stage('ci-sgx1-debug') {
      steps {
        sh './scripts/test-build-config -p SGX1FLC -b Debug '
        echo 'ci-sgx1-debug'
      }
    }
  }
}