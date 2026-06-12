FROM ubuntu:22.04

# Set environment variables
ENV TOMCAT_USER=tomcat
ENV TOMCAT_GROUP=tomcat
ENV TOMCAT_HOME=/opt/tomcat

# Install required packages
RUN apt-get update && \
    apt-get install -y openssh-client default-jdk wget && \
    groupadd $TOMCAT_GROUP && \
    useradd -g $TOMCAT_GROUP -d $TOMCAT_HOME -s /bin/bash $TOMCAT_USER && \
    mkdir -p $TOMCAT_HOME && \
    chown $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME

RUN apt-get install -y sshpass nmap ncat python3 python3-pip net-tools curl wget unzip

# Install nuclei from its prebuilt release binary (arch-aware) instead of compiling
# from source. The old `go install` approach pulled 1000+ Go modules and could take
# HOURS over a slow link; this is a single ~30MB download that finishes in seconds.
# No Go toolchain is needed anymore -- nuclei was the only thing that used it.
# TARGETARCH is auto-injected by BuildKit (amd64 on Intel, arm64 on Apple Silicon)
# and matches nuclei's asset naming, so this works natively on either chip.
ARG TARGETARCH
ENV NUCLEI_VERSION=3.9.0
# If GitHub is slow from your network, prepend a mirror, e.g.
#   ENV NUCLEI_URL=https://ghfast.top/https://github.com/projectdiscovery/...
ENV NUCLEI_URL=https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip
RUN wget -O /tmp/nuclei.zip "${NUCLEI_URL}" && \
    unzip /tmp/nuclei.zip -d /tmp/nuclei && \
    mv /tmp/nuclei/nuclei /usr/local/bin/nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei /tmp/nuclei.zip

# Set default shell to be bash
RUN chsh -s /bin/bash $TOMCAT_USER

COPY struts/tomcat.zip /tmp/tomcat.zip

# Download and install Tomcat
RUN unzip /tmp/tomcat.zip -d /tmp && \
    mv /tmp/tomcat/* $TOMCAT_HOME/ && \
    rm -rf /tmp/tomcat /tmp/tomcat.zip && \
    chown -R $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME

# Create necessary directories and files for the Tomcat user
RUN mkdir -p $TOMCAT_HOME/.ssh && \
    touch $TOMCAT_HOME/.ssh/config && \
    chown -R $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME && \
    chmod 700 $TOMCAT_HOME/.ssh && \
    chmod 600 $TOMCAT_HOME/.ssh/config

# Expose port for Tomcat
EXPOSE 8080

# Create .ssh directory and copy config
COPY ssh/config $TOMCAT_HOME/.ssh/config
RUN chown $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME/.ssh/config && \
    chmod 600 $TOMCAT_HOME/.ssh/config

# Add id_rsa file
COPY ssh/id_rsa $TOMCAT_HOME/.ssh/id_rsa
COPY ssh/id_rsa.pub $TOMCAT_HOME/.ssh/id_rsa.pub
RUN chown $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME/.ssh/id_rsa && \
    chmod 600 $TOMCAT_HOME/.ssh/id_rsa && \
    chown $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME/.ssh/id_rsa.pub && \
    chmod 644 $TOMCAT_HOME/.ssh/id_rsa.pub

# Set execution permissions and run Tomcat
USER $TOMCAT_USER
CMD ["/opt/tomcat/bin/catalina.sh", "run", ">", "/dev/null", "2>&1"]
