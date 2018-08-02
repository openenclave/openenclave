pipeline {
  agent {
    docker {
      image 'oetools-jenkins:0.1'
    }

  }
  stages {
    stage('test') {
      steps {
        echo 'test'
        sh '''pwd

ls -l

whoami'''
      }
    }
  }
}