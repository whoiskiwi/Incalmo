FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sshpass nmap ncat curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m user2 && chsh -s /bin/bash user2

RUN mkdir -p /home/user2/.ssh && \
    chown -R user2:user2 /home/user2/.ssh && \
    chmod 700 /home/user2/.ssh

COPY authorized_keys /home/user2/.ssh/authorized_keys
COPY ssh/config      /home/user2/.ssh/config
COPY ssh/id_rsa      /home/user2/.ssh/id_rsa
COPY ssh/id_rsa.pub  /home/user2/.ssh/id_rsa.pub

RUN chown user2:user2 /home/user2/.ssh/authorized_keys \
        /home/user2/.ssh/config \
        /home/user2/.ssh/id_rsa \
        /home/user2/.ssh/id_rsa.pub && \
    chmod 600 /home/user2/.ssh/authorized_keys \
              /home/user2/.ssh/config \
              /home/user2/.ssh/id_rsa && \
    chmod 644 /home/user2/.ssh/id_rsa.pub

RUN mkdir /var/run/sshd
CMD ["/usr/sbin/sshd", "-D"]
