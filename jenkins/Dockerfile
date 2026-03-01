FROM jenkins/jenkins:lts-jdk17

USER root

# Install Docker CLI so the Docker Pipeline plugin can spin up containers
RUN apt-get update && \
    apt-get install -y ca-certificates curl && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce-cli && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Pre-install required plugins
RUN jenkins-plugin-cli --plugins \
    docker-workflow \
    http_request \
    warnings-ng \
    git \
    workflow-aggregator \
    credentials-binding

USER jenkins
