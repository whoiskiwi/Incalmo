FROM ubuntu:22.04

ENV TOMCAT_USER=tomcat
ENV TOMCAT_GROUP=tomcat
ENV TOMCAT_HOME=/opt/tomcat

RUN apt-get update && \
    apt-get install -y openssh-client default-jdk wget && \
    groupadd $TOMCAT_GROUP && \
    useradd -g $TOMCAT_GROUP -d $TOMCAT_HOME -s /bin/bash $TOMCAT_USER && \
    mkdir -p $TOMCAT_HOME && \
    chown $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME

RUN apt-get install -y sshpass nmap ncat python3 python3-pip net-tools curl wget unzip

ARG TARGETARCH
ENV NUCLEI_VERSION=3.9.0
ENV NUCLEI_URL=https://ghfast.top/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip
RUN wget -O /tmp/nuclei.zip "${NUCLEI_URL}" && \
    unzip /tmp/nuclei.zip -d /tmp/nuclei && \
    mv /tmp/nuclei/nuclei /usr/local/bin/nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei /tmp/nuclei.zip

RUN chsh -s /bin/bash $TOMCAT_USER

COPY struts/tomcat.zip /tmp/tomcat.zip
RUN unzip /tmp/tomcat.zip -d /tmp && \
    mv /tmp/tomcat/* $TOMCAT_HOME/ && \
    rm -rf /tmp/tomcat /tmp/tomcat.zip && \
    chown -R $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME

RUN mkdir -p $TOMCAT_HOME/.ssh && \
    chown -R $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME && \
    chmod 700 $TOMCAT_HOME/.ssh

COPY ssh/config $TOMCAT_HOME/.ssh/config
COPY ssh/id_rsa $TOMCAT_HOME/.ssh/id_rsa
COPY ssh/id_rsa.pub $TOMCAT_HOME/.ssh/id_rsa.pub
RUN chown $TOMCAT_USER:$TOMCAT_GROUP $TOMCAT_HOME/.ssh/config \
        $TOMCAT_HOME/.ssh/id_rsa $TOMCAT_HOME/.ssh/id_rsa.pub && \
    chmod 600 $TOMCAT_HOME/.ssh/config $TOMCAT_HOME/.ssh/id_rsa && \
    chmod 644 $TOMCAT_HOME/.ssh/id_rsa.pub

EXPOSE 8080
USER $TOMCAT_USER
CMD ["/opt/tomcat/bin/catalina.sh", "run"]
