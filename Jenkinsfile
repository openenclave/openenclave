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

sudo git config --global user.email "oeciteam@microsoft.com"
sudo git config --global user.name "OE CI Team"


git pull origin master --no-edit'''
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