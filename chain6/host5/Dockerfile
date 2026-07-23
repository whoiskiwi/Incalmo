FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sshpass nmap ncat curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m user5 && chsh -s /bin/bash user5

RUN mkdir -p /home/user5/.ssh && \
    chown -R user5:user5 /home/user5/.ssh && \
    chmod 700 /home/user5/.ssh

COPY authorized_keys /home/user5/.ssh/authorized_keys
COPY ssh/config      /home/user5/.ssh/config
COPY ssh/id_rsa      /home/user5/.ssh/id_rsa
COPY ssh/id_rsa.pub  /home/user5/.ssh/id_rsa.pub

RUN chown user5:user5 /home/user5/.ssh/authorized_keys \
        /home/user5/.ssh/config \
        /home/user5/.ssh/id_rsa \
        /home/user5/.ssh/id_rsa.pub && \
    chmod 600 /home/user5/.ssh/authorized_keys \
              /home/user5/.ssh/config \
              /home/user5/.ssh/id_rsa && \
    chmod 644 /home/user5/.ssh/id_rsa.pub

RUN mkdir /var/run/sshd
CMD ["/usr/sbin/sshd", "-D"]
