pipeline {
    agent {
        label 'ecev-cicd'
    }
    stages {
        stage('Prepare artifact'){
            steps {
                sh 'cd "/usr/src/ecev-workspace/workspace/ecev-utility"'
                sh 'rm -rf app.zip'
                sh 'zip -r app.zip . -x django_env -x db.sqlite3'
                sh 'sudo cp /usr/src/ecev-workspace/workspace/ecev-utility/app.zip /home/ubuntu/artifact-ecev-utility'
                sh 'sudo unzip -o /home/ubuntu/artifact-ecev-utility/app.zip -d /usr/src/ecev-utility'
                sh 'sudo chown ubuntu:ubuntu /usr/src/ecev-utility/**/**'
            }
        }
        stage('Setup Python Virtual Environment'){
            steps {
                sh '''
                    chmod +x envsetup.sh
                    ./envsetup.sh
                    '''
            }
        }
        
        stage('Setup gunicorn service'){
            steps {
                sh '''
                    cd /usr/src/ecev-utility
                    sudo chmod +x gunicorn.sh
                    ./gunicorn.sh
                    '''
            }
        }
    }
    post {
        success {
            sh 'echo hello' 
        }
    }
}