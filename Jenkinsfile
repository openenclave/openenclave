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
        sh './scripts/check-precommit-reqs'
      }
    }
  }
}