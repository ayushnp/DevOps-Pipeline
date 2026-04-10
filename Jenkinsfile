pipeline {
    agent any

    environment {
        DOCKERHUB_USER = "ayushnp10"
        IMAGE = "ayushnp10/devopsaba:latest"
        IMAGE_VERSION = "ayushnp10/devopsaba:${BUILD_NUMBER}"
        LAST_SUCCESS_FILE = "last_success_image.txt"
    }

    stages {

        /* --------------------------------------------------------
           CHECKOUT SOURCE CODE
        -------------------------------------------------------- */
        stage('Checkout Code') {
            steps { checkout scm }
        }

        /* --------------------------------------------------------
           SECURITY SCAN — GITLEAKS
        -------------------------------------------------------- */
        stage('Secret Scan (Gitleaks)') {
            steps {
                bat """
                    docker run --rm ^
                        -v %CD%:/repo ^
                        zricethezav/gitleaks:latest detect ^
                        --source=/repo ^
                        --exit-code 1 ^
                        --redact
                """
            }
        }

        /* --------------------------------------------------------
           SECURITY SCAN — TRIVY FS
        -------------------------------------------------------- */
        stage('Trivy FS Scan') {
            steps {
                bat """
                    docker run --rm ^
                        -v %CD%:/repo ^
                        aquasec/trivy:latest fs /repo ^
                        --severity HIGH,CRITICAL ^
                        --ignore-unfixed ^
                        --exit-code 1
                """
            }
        }

        /* --------------------------------------------------------
           BUILD DOCKER IMAGE
        -------------------------------------------------------- */
        stage('Build Docker Image') {
            steps {
                bat """
                    docker build -t %IMAGE_VERSION% .
                    docker tag %IMAGE_VERSION% %IMAGE%
                """
            }
        }

        /* --------------------------------------------------------
           IMAGE VULNERABILITY SCAN (OPTION 3 APPLIED)
        -------------------------------------------------------- */
        stage('Image Scan (Trivy Image)') {
            steps {
                bat """
                    docker run --rm aquasec/trivy:latest image %IMAGE% ^
                        --severity HIGH,CRITICAL ^
                        --ignore-unfixed ^
                        --exit-code 1
                """
            }
        }

        /* --------------------------------------------------------
           DOCKER HUB LOGIN
        -------------------------------------------------------- */
        stage('DockerHub Login') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-creds',
                    usernameVariable: 'USER',
                    passwordVariable: 'PASS'
                )]) {
                    bat """ echo %PASS% | docker login -u %USER% --password-stdin """
                }
            }
        }

        /* --------------------------------------------------------
           PUSH IMAGE
        -------------------------------------------------------- */
        stage('Push Image') {
            steps {
                bat """
                    docker push %IMAGE_VERSION%
                    docker push %IMAGE%
                """
            }
        }

        /* --------------------------------------------------------
           DEPLOY TO PRODUCTION
        -------------------------------------------------------- */
        stage('Deploy to Production') {
            steps {
                bat """
                    docker stop devopsaba || echo No container
                    docker rm devopsaba || echo No container
                    docker run -d -p 5000:5000 --name devopsaba %IMAGE%
                """
            }
        }

        /* --------------------------------------------------------
           AUTO-ROLLBACK SYSTEM
        -------------------------------------------------------- */
        stage('Verify & Auto Rollback') {
            steps {
                script {

                    def running = bat(
                        script: 'docker inspect -f "{{.State.Running}}" devopsaba 2>NUL',
                        returnStdout: true
                    ).trim().toLowerCase()

                    if (!running.contains("true")) {
                        echo "❌ Deployment Failed — Starting Rollback..."

                        bat "docker stop devopsaba || echo No container"
                        bat "docker rm devopsaba || echo No container"

                        if (!fileExists(env.LAST_SUCCESS_FILE)) {
                            error("❗ No previous stable image exists for rollback.")
                        }

                        def last = readFile(env.LAST_SUCCESS_FILE).trim()

                        bat "docker run -d -p 5000:5000 --name devopsaba ${last}"

                        error("Rollback executed — Deployment failed.")
                    }

                    writeFile file: env.LAST_SUCCESS_FILE, text: env.IMAGE_VERSION
                    echo "✔ Deployment Healthy — Saved as stable"
                }
            }
        }
    }

    /* --------------------------------------------------------
       POST: EMAIL + SLACK NOTIFICATIONS
    -------------------------------------------------------- */
    post {

        success {
            slackSend(
                channel: '#ci-cd-pipeline',
                tokenCredentialId: 'ae899829-98fa-4f99-b61b-9b966850cb88',
                message: "✅ SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
            )

            emailext(
                to: "ayushkotegar10@gmail.com, aadyambhat2005@gmail.com, lohithbandla5@gmail.com, bhargavisriinivas@gmail.com",
                subject: "SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
Hello Team,

The CI/CD pipeline completed successfully.

Job: ${env.JOB_NAME}
Build Number: ${env.BUILD_NUMBER}
Status: SUCCESS

Build Log:
${env.BUILD_URL}console

Regards,
Jenkins
                """,
                attachLog: true
            )
        }

        failure {
            slackSend(
                channel: '#ci-cd-pipeline',
                tokenCredentialId: 'ae899829-98fa-4f99-b61b-9b966850cb88',
                message: "❌ FAILURE: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
            )

            emailext(
                to: "ayushkotegar10@gmail.com, aadyambhat2005@gmail.com, lohithbandla5@gmail.com, bhargavisriinivas@gmail.com",
                subject: "FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
Hello Team,

The CI/CD pipeline has FAILED.

Job: ${env.JOB_NAME}
Build Number: ${env.BUILD_NUMBER}

View logs:
${env.BUILD_URL}console

Regards,
Jenkins
                """,
                attachLog: true
            )
        }
    }
}
