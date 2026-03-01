pipeline {
    agent any

    environment {
        // Dependency Track configuration
        DEPENDENCY_TRACK_URL    = credentials('dependency-track-url')
        DEPENDENCY_TRACK_API_KEY = credentials('dependency-track-api-key')
        DEPENDENCY_TRACK_PROJECT_NAME = 'VAmPI'
        DEPENDENCY_TRACK_PROJECT_VERSION = "${env.BRANCH_NAME ?: 'main'}"

        // Report output paths
        SEMGREP_REPORT  = 'reports/semgrep-results.json'
        SEMGREP_SARIF   = 'reports/semgrep-results.sarif'
        SBOM_OUTPUT     = 'reports/bom.json'
    }

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh 'mkdir -p reports'
            }
        }

        // ─────────────────────────────────────────────
        // SAST — Semgrep
        // ─────────────────────────────────────────────
        stage('SAST — Semgrep') {
            agent {
                docker {
                    image 'semgrep/semgrep:latest'
                    reuseNode true
                    args '--entrypoint=""'
                }
            }
            steps {
                script {
                    // Run with the standard Python security + OWASP rulesets.
                    // --error makes Semgrep exit 1 when findings exist; remove it
                    // if you want the pipeline to continue regardless.
                    def semgrepStatus = sh(
                        script: """
                            semgrep scan \
                                --config "p/python" \
                                --config "p/owasp-top-ten" \
                                --config "p/flask" \
                                --json --output ${SEMGREP_REPORT} \
                                --sarif --output ${SEMGREP_SARIF} \
                                --metrics=off \
                                .
                        """,
                        returnStatus: true
                    )

                    if (semgrepStatus == 1) {
                        echo 'Semgrep found security findings — check the report.'
                        currentBuild.result = 'UNSTABLE'
                    } else if (semgrepStatus > 1) {
                        error "Semgrep failed with exit code ${semgrepStatus}"
                    }
                }
            }
            post {
                always {
                    // Publish SARIF report (requires Warnings Next Generation plugin)
                    recordIssues(
                        tools: [sarif(pattern: "${SEMGREP_SARIF}", name: 'Semgrep SAST')],
                        qualityGates: [[threshold: 1, type: 'TOTAL_HIGH', unstable: true]]
                    )
                    archiveArtifacts artifacts: 'reports/semgrep-*', allowEmptyArchive: true
                }
            }
        }

        // ─────────────────────────────────────────────
        // SCA — Generate SBOM with cdxgen
        // ─────────────────────────────────────────────
        stage('SCA — Generate SBOM (cdxgen)') {
            agent {
                docker {
                    image 'ghcr.io/cyclonedx/cdxgen:latest'
                    reuseNode true
                    args '--entrypoint="" -e FETCH_LICENSE=true -e GITHUB_TOKEN=""'
                }
            }
            steps {
                sh """
                    cdxgen \
                        --type python \
                        --output ${SBOM_OUTPUT} \
                        --project-name "${DEPENDENCY_TRACK_PROJECT_NAME}" \
                        --project-version "${DEPENDENCY_TRACK_PROJECT_VERSION}" \
                        .
                """
                archiveArtifacts artifacts: "${SBOM_OUTPUT}", allowEmptyArchive: false
            }
        }

        // ─────────────────────────────────────────────
        // SCA — Upload SBOM to Dependency Track
        // ─────────────────────────────────────────────
        stage('SCA — Upload to Dependency Track') {
            steps {
                script {
                    def bomBase64 = sh(
                        script: "base64 -w 0 ${SBOM_OUTPUT}",
                        returnStdout: true
                    ).trim()

                    def payload = groovy.json.JsonOutput.toJson([
                        projectName   : env.DEPENDENCY_TRACK_PROJECT_NAME,
                        projectVersion: env.DEPENDENCY_TRACK_PROJECT_VERSION,
                        autoCreate    : true,
                        bom           : bomBase64
                    ])

                    def response = httpRequest(
                        httpMode       : 'PUT',
                        url            : "${DEPENDENCY_TRACK_URL}/api/v1/bom",
                        contentType    : 'APPLICATION_JSON',
                        requestBody    : payload,
                        customHeaders  : [[name: 'X-Api-Key', value: env.DEPENDENCY_TRACK_API_KEY]],
                        validResponseCodes: '200:201'
                    )

                    echo "Dependency Track response: ${response.status}"
                    echo "SBOM uploaded. Check Dependency Track for vulnerability analysis."
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline finished — status: ${currentBuild.currentResult}"
        }
        success {
            echo 'All security scans completed successfully.'
        }
        unstable {
            echo 'Security findings were detected. Review Semgrep and Dependency Track reports.'
        }
        failure {
            echo 'Pipeline failed. Check the logs for errors.'
        }
    }
}
