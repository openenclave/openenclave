pipeline {
  agent {
    docker {
      image 'hello-world'
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