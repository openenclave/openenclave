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

whoami'''
      }
    }
    stage('Precommit-checking') {
      steps {
        echo 'Precommit-checking'
        sh './scripts/check-precommit-reqs'
      }
    }
  }
}