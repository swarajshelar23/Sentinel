pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    environment {
        NODE_ENV = 'production'
        DOCKER_IMAGE_NAME = 'sentinel'
        DOCKER_IMAGE_TAG = "${env.BUILD_NUMBER}"
        DOCKER_HUB_IMAGE = 'myhub/sentinel'
        DOCKERHUB_CREDENTIALS_ID = 'dockerhub-creds'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                script {
                    if (isUnix()) {
                        sh 'npm ci'
                    } else {
                        bat 'npm ci'
                    }
                }
            }
        }

        stage('Type Check') {
            steps {
                script {
                    if (isUnix()) {
                        sh 'npm run lint'
                    } else {
                        bat 'npm run lint'
                    }
                }
            }
        }

        stage('Build') {
            steps {
                script {
                    if (isUnix()) {
                        sh 'npm run build'
                    } else {
                        bat 'npm run build'
                    }
                }
            }
        }

        stage('Docker Build') {
            when {
                expression { fileExists('Dockerfile') }
            }
            steps {
                script {
                    if (isUnix()) {
                        sh 'docker build -t ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} .'
                    } else {
                        bat 'docker build -t %DOCKER_IMAGE_NAME%:%DOCKER_IMAGE_TAG% .'
                    }
                }
            }
        }

        stage('Push Docker Hub Image') {
            when {
                expression { fileExists('Dockerfile') }
            }
            steps {
                script {
                    if (isUnix()) {
                        withCredentials([usernamePassword(credentialsId: env.DOCKERHUB_CREDENTIALS_ID, usernameVariable: 'DOCKERHUB_USER', passwordVariable: 'DOCKERHUB_PASS')]) {
                            sh '''
                                set -e
                                docker tag ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} ${DOCKER_HUB_IMAGE}:${DOCKER_IMAGE_TAG}
                                docker tag ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} ${DOCKER_HUB_IMAGE}:latest

                                printf '%s' "$DOCKERHUB_PASS" | docker login -u "$DOCKERHUB_USER" --password-stdin
                                docker push ${DOCKER_HUB_IMAGE}:${DOCKER_IMAGE_TAG}
                                docker push ${DOCKER_HUB_IMAGE}:latest
                                docker logout
                            '''
                        }
                    } else {
                        withCredentials([usernamePassword(credentialsId: env.DOCKERHUB_CREDENTIALS_ID, usernameVariable: 'DOCKERHUB_USER', passwordVariable: 'DOCKERHUB_PASS')]) {
                            bat '''
                                docker tag %DOCKER_IMAGE_NAME%:%DOCKER_IMAGE_TAG% %DOCKER_HUB_IMAGE%:%DOCKER_IMAGE_TAG%
                                docker tag %DOCKER_IMAGE_NAME%:%DOCKER_IMAGE_TAG% %DOCKER_HUB_IMAGE%:latest

                                echo %DOCKERHUB_PASS% | docker login -u %DOCKERHUB_USER% --password-stdin
                                docker push %DOCKER_HUB_IMAGE%:%DOCKER_IMAGE_TAG%
                                docker push %DOCKER_HUB_IMAGE%:latest
                                docker logout
                            '''
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'dist/**', fingerprint: true, allowEmptyArchive: true
            cleanWs()
        }
        failure {
            echo 'Build failed. Check the console output for the failing stage.'
        }
    }
}