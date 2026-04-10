def rotateSecret(String ruleId) {
    withCredentials([
        string(credentialsId: 'aws-access-key', variable: 'AWS_ACCESS_KEY_ID'),
        string(credentialsId: 'aws-secret-key', variable: 'AWS_SECRET_ACCESS_KEY')
    ]) {
        bat """
            docker run --rm ^
                -e AWS_ACCESS_KEY_ID=%AWS_ACCESS_KEY_ID% ^
                -e AWS_SECRET_ACCESS_KEY=%AWS_SECRET_ACCESS_KEY% ^
                -e AWS_DEFAULT_REGION=ap-south-1 ^
                amazon/aws-cli secretsmanager rotate-secret ^
                --secret-id devopsaba/${ruleId} ^
                --rotate-immediately
        """
        echo "✅ Secret rotation triggered for rule: ${ruleId}"
    }
}

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
           SECURITY SCAN — GITLEAKS (with location alert + rotation)
        -------------------------------------------------------- */
        stage('Secret Scan (Gitleaks)') {
            steps {
                script {
                    // Run Gitleaks and always output JSON report; don't fail yet
                    bat """
                        docker run --rm ^
                            -v %CD%:/repo ^
                            zricethezav/gitleaks:latest detect ^
                            --source=/repo ^
                            --report-format=json ^
                            --report-path=/repo/gitleaks-report.json ^
                            --redact ^
                            --exit-code 0
                    """

                    if (fileExists('gitleaks-report.json')) {
                        def reportText = readFile('gitleaks-report.json').trim()

                        // Empty array or null means clean
                        if (reportText && reportText != '[]' && reportText != 'null') {
                            def report = readJSON text: reportText

                            if (report && report.size() > 0) {

                                // Build a detailed summary of every leak found
                                def leakSummary = report.collect { leak ->
                                    "• File: ${leak.File} | Line: ${leak.StartLine} | Rule: ${leak.RuleID} | Commit: ${leak.Commit?.take(8)} | Author: ${leak.Author}"
                                }.join('\n')

                                def alertMsg = """
🚨 SECRET LEAK DETECTED — ${env.JOB_NAME} #${env.BUILD_NUMBER}
Pipeline has been BLOCKED. Secrets found:

${leakSummary}

Build URL: ${env.BUILD_URL}
Action: Exposed credentials are being auto-rotated via AWS Secrets Manager.
"""
                                // Send Slack alert with exact locations
                                slackSend(
                                    channel: '#ci-cd-pipeline',
                                    tokenCredentialId: 'ae899829-98fa-4f99-b61b-9b966850cb88',
                                    message: alertMsg
                                )

                                // Send email alert with exact locations
                                emailext(
                                    to: "ayushkotegar10@gmail.com, aadyambhat2005@gmail.com, lohithbandla5@gmail.com, bhargavisriinivas@gmail.com",
                                    subject: "🚨 SECRET LEAK DETECTED: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                                    body: alertMsg,
                                    attachLog: true
                                )

                                // Auto-rotate each unique rule/secret type found
                                def rotatedRules = []
                                report.each { leak ->
                                    if (!rotatedRules.contains(leak.RuleID)) {
                                        rotateSecret(leak.RuleID)
                                        rotatedRules.add(leak.RuleID)
                                    }
                                }

                                // Now block the pipeline
                                error("🚨 Pipeline blocked: ${report.size()} secret(s) detected. Check Slack/email for exact locations. Rotation has been triggered.")
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
           IMAGE VULNERABILITY SCAN — CVEs + SECRETS IN LAYERS
        -------------------------------------------------------- */
        stage('Image Scan (Trivy Image)') {
            steps {
                script {
                    // Pass 1: CVE scan (original behaviour)
                    bat """
                        docker run --rm aquasec/trivy:latest image %IMAGE% ^
                            --severity HIGH,CRITICAL ^
                            --ignore-unfixed ^
                            --exit-code 1
                    """

                    // Pass 2: Secret scan on built image layers (new)
                    def secretStatus = bat(
                        script: """
                            docker run --rm ^
                                aquasec/trivy:latest image %IMAGE% ^
                                --scanners secret ^
                                --format json ^
                                --exit-code 0 ^
                                --output trivy-image-secrets.json
                        """,
                        returnStatus: true
                    )

                    if (fileExists('trivy-image-secrets.json')) {
                        def trivyReport = readJSON file: 'trivy-image-secrets.json'
                        def findings = trivyReport?.Results?.findAll { it.Secrets }?.collectMany { it.Secrets } ?: []

                        if (findings.size() > 0) {
                            def trivyMsg = """
🚨 SECRETS FOUND IN DOCKER IMAGE LAYERS — ${env.JOB_NAME} #${env.BUILD_NUMBER}
${findings.collect { s -> "• [${s.RuleID}] ${s.Title} at ${s.Target}:${s.StartLine}" }.join('\n')}

Image: %IMAGE%
Action: Image will NOT be pushed. Rotation triggered.
"""
                            slackSend(
                                channel: '#ci-cd-pipeline',
                                tokenCredentialId: 'ae899829-98fa-4f99-b61b-9b966850cb88',
                                message: triyvMsg
                            )
                            emailext(
                                to: "ayushkotegar10@gmail.com, aadyambhat2005@gmail.com, lohithbandla5@gmail.com, bhargavisriinivas@gmail.com",
                                subject: "🚨 SECRET IN IMAGE: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                                body: triyvMsg,
                                attachLog: true
                            )

                            findings.each { s -> rotateSecret(s.RuleID) }
                            error("🚨 Pipeline blocked: secrets found in Docker image layers. Image will NOT be pushed to DockerHub.")
                        }
                    }

                    echo "✅ Trivy image secret scan: clean."
                }
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

Build Log: ${env.BUILD_URL}console

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

View logs: ${env.BUILD_URL}console

Regards,
Jenkins
                """,
                attachLog: true
            )
        }
    }
}