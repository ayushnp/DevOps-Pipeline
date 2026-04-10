/* --------------------------------------------------------
   HELPER: SECRET ROTATION VIA GCP SECRET MANAGER
-------------------------------------------------------- */
def rotateSecret(String ruleId) {
    // Replace 'gcp-secret-manager-key' with the ID of the JSON key you upload to Jenkins
    withCredentials([file(credentialsId: 'gcp-secret-manager-key', variable: 'GCP_KEY')]) {
        bat """
            set GOOGLE_APPLICATION_CREDENTIALS=%GCP_KEY%
            python rotate_secrets.py leaks.json
        """
        echo "✅ GCP Secret rotation triggered for rule: ${ruleId}"
    }
}

pipeline {
    agent any

    environment {
        DOCKERHUB_USER = "ayushnp10"
        IMAGE = "ayushnp10/devopsaba:latest"
        IMAGE_VERSION = "ayushnp10/devopsaba:${BUILD_NUMBER}"
        LAST_SUCCESS_FILE = "last_success_image.txt"
        // Replace with your actual GCP Project ID
        GCP_PROJECT_ID = "ci-cd-pipeline-492918" 
    }

    stages {
        /* --------------------------------------------------------
           CHECKOUT SOURCE CODE
        -------------------------------------------------------- */
        stage('Checkout Code') {
            steps { checkout scm }
        }

        /* --------------------------------------------------------
           SECURITY SCAN — GITLEAKS (with Auto-Rotation)
        -------------------------------------------------------- */
        stage('Secret Scan (Gitleaks)') {
            steps {
                script {
                    // 1. Run Gitleaks and generate JSON report
                    bat """
                        docker run --rm ^
                            -v %CD%:/repo ^
                            zricethezav/gitleaks:latest detect ^
                            --source=/repo ^
                            --report-format=json ^
                            --report-path=/repo/leaks.json ^
                            --redact ^
                            --exit-code 0
                    """

                    // 2. Analyze the report
                    if (fileExists('leaks.json')) {
                        def reportText = readFile('leaks.json').trim()

                        if (reportText && reportText != '[]' && reportText != 'null') {
                            def report = readJSON text: reportText

                            if (report && report.size() > 0) {
                                def leakSummary = report.collect { leak ->
                                    "• File: ${leak.File} | Line: ${leak.StartLine} | Rule: ${leak.RuleID}"
                                }.join('\n')

                                def alertMsg = """
🚨 SECRET LEAK DETECTED — ${env.JOB_NAME} #${env.BUILD_NUMBER}
Pipeline BLOCKED. Secrets found at:

${leakSummary}

Action: Credentials are being auto-rotated via GCP Secret Manager.
"""
                                // Send Notifications
                                slackSend(channel: '#ci-cd-pipeline', tokenCredentialId: 'ae899829-98fa-4f99-b61b-9b966850cb88', message: alertMsg)
                                
                                // Trigger Rotation for each unique secret type
                                def rotatedRules = []
                                report.each { leak ->
                                    if (!rotatedRules.contains(leak.RuleID)) {
                                        rotateSecret(leak.RuleID)
                                        rotatedRules.add(leak.RuleID)
                                    }
                                }

                                error("🚨 Pipeline blocked: ${report.size()} secret(s) detected. Rotation triggered.")
                            }
                        }
                    }
                    echo "✅ Gitleaks: No secrets found. Proceeding."
                }
            }
        }

        /* --------------------------------------------------------
           SECURITY SCAN — TRIVY FS
        -------------------------------------------------------- */
        stage('Trivy FS Scan') {
            steps {
                bat "docker run --rm -v %CD%:/repo aquasec/trivy:latest fs /repo --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1"
            }
        }

        /* --------------------------------------------------------
           BUILD DOCKER IMAGE
        -------------------------------------------------------- */
        stage('Build Docker Image') {
            steps {
                bat "docker build -t %IMAGE_VERSION% ."
                bat "docker tag %IMAGE_VERSION% %IMAGE%"
            }
        }

        /* --------------------------------------------------------
           IMAGE VULNERABILITY & SECRET SCAN
        -------------------------------------------------------- */
        stage('Image Scan (Trivy Image)') {
            steps {
                script {
                    // CVE Scan
                    bat "docker run --rm aquasec/trivy:latest image %IMAGE% --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1"

                    // Secret Scan on Layers
                    def secretStatus = bat(
                        script: "docker run --rm aquasec/trivy:latest image %IMAGE% --scanners secret --format json --output trivy-image-secrets.json --exit-code 0",
                        returnStatus: true
                    )

                    if (fileExists('trivy-image-secrets.json')) {
                        def trivyReport = readJSON file: 'trivy-image-secrets.json'
                        def findings = trivyReport?.Results?.findAll { it.Secrets }?.collectMany { it.Secrets } ?: []

                        if (findings.size() > 0) {
                            def trivyMsg = "🚨 SECRETS FOUND IN IMAGE LAYERS: ${findings.size()} findings. Rotation triggered."
                            slackSend(channel: '#ci-cd-pipeline', tokenCredentialId: 'ae899829-98fa-4f99-b61b-9b966850cb88', message: trivyMsg)
                            
                            findings.each { s -> rotateSecret(s.RuleID) }
                            error("🚨 Pipeline blocked: secrets found in Docker image layers.")
                        }
                    }
                }
            }
        }

        /* --------------------------------------------------------
           DOCKER HUB LOGIN & PUSH
        -------------------------------------------------------- */
        stage('Push to DockerHub') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds', usernameVariable: 'USER', passwordVariable: 'PASS')]) {
                    bat "echo %PASS% | docker login -u %USER% --password-stdin"
                }
                bat "docker push %IMAGE_VERSION%"
                bat "docker push %IMAGE%"
            }
        }

        /* --------------------------------------------------------
           DEPLOY & ROLLBACK logic
        -------------------------------------------------------- */
        stage('Deploy to Production') {
            steps {
                bat "docker stop devopsaba || echo No container"
                bat "docker rm devopsaba || echo No container"
                bat "docker run -d -p 5000:5000 --name devopsaba %IMAGE%"
            }
        }

        stage('Verify & Auto Rollback') {
            steps {
                script {
                    def running = bat(script: 'docker inspect -f "{{.State.Running}}" devopsaba 2>NUL', returnStdout: true).trim().toLowerCase()
                    if (!running.contains("true")) {
                        echo "❌ Deployment Failed — Starting Rollback..."
                        bat "docker stop devopsaba || echo No container"
                        bat "docker rm devopsaba || echo No container"
                        def last = readFile(env.LAST_SUCCESS_FILE).trim()
                        bat "docker run -d -p 5000:5000 --name devopsaba ${last}"
                        error("Rollback executed.")
                    }
                    writeFile file: env.LAST_SUCCESS_FILE, text: env.IMAGE_VERSION
                    echo "✔ Deployment Healthy"
                }
            }
        }
    }

    post {
        success {
            slackSend(channel: '#ci-cd-pipeline', tokenCredentialId: 'ae899829-98fa-4f99-b61b-9b966850cb88', message: "✅ SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}")
        }
        failure {
            slackSend(channel: '#ci-cd-pipeline', tokenCredentialId: 'ae899829-98fa-4f99-b61b-9b966850cb88', message: "❌ FAILURE: ${env.JOB_NAME} #${env.BUILD_NUMBER}")
        }
    }
}