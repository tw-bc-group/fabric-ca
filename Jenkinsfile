def getRepoURL() {
  sh "git config --get remote.origin.url > .git/remote-url"
  return readFile(".git/remote-url").trim()
}

def projectName = "hyperledger/fabric-ca"

void setBuildStatus(String message, String state) {
  repoUrl = getRepoURL()

  step([
      $class: "GitHubCommitStatusSetter",
      reposSource: [$class: "ManuallyEnteredRepositorySource", url: repoUrl],
      contextSource: [$class: "ManuallyEnteredCommitContextSource", context: "ci/jenkins/build-status"],
      errorHandlers: [[$class: "ChangingBuildStatusErrorHandler", result: "UNSTABLE"]],
      statusResultSource: [ $class: "ConditionalStatusResultSource", results: [[$class: "AnyBuildResult", message: message, state: state]] ]
  ]);
}

pipeline {
    agent any

    environment {
        DOCKER_NS     = "twblockchain"
        EXTRA_VERSION = "build-${BUILD_NUMBER}"
        GOPATH        = "${WORKSPACE}/gopath"
    }

    stages {
        stage('Build Image') {
            steps {
                setBuildStatus("Build Started", "PENDING");

                dir("gopath/src/github.com/$projectName") {
                    checkout scm

                    sh '''
                    make clean docker
                    '''
                }
            }
        }
        stage('Upload Image') {
            steps {
                dir("gopath/src/github.com/$projectName") {
                    sh '''
                    make docker-list 2>/dev/null | grep "$DOCKER_NS" | while read line
                    do
                       docker tag $line ${line/:*/:latest}

                       docker push $line
                       docker push ${line/:*/:latest}

                       docker rmi $line
                       docker rmi ${line/:*/:latest}
                    done
                    '''
                }
            }
        }

        stage('Test Fabcar') {
            steps {
                dir("gopath/src/github.com/$projectName") {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        script {
                            def result = build(
                                job: 'fabric-samples',
                                propagate: false,
                                parameters: [
                                    [$class: 'StringParameterValue', name: 'BYFN_CA', value: 'yes'],
                                    [$class: 'StringParameterValue', name: 'IMAGE_CA', value: sh(script: 'make fabric-ca-docker-list 2>/dev/null ', returnStdout: true).trim()],
                                ]
                            )
                            if (result.result.equals("SUCCESS")) {
                                echo "Passed Test Fabcar"
                            } else {
                                error "Failed Test Fabcar"
                            }
                        }
                    }
                }
            }
        }
    }

    post {
        success {
            setBuildStatus("Build succeeded", "SUCCESS");
        }
        unsuccessful {
            setBuildStatus("Build failed", "FAILURE");
        }
    }
}
