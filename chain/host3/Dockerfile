FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sshpass nmap ncat curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m user3 && chsh -s /bin/bash user3

RUN mkdir -p /home/user3/.ssh && \
    chown -R user3:user3 /home/user3/.ssh && \
    chmod 700 /home/user3/.ssh

COPY authorized_keys /home/user3/.ssh/authorized_keys
COPY ssh/config      /home/user3/.ssh/config
COPY ssh/id_rsa      /home/user3/.ssh/id_rsa
COPY ssh/id_rsa.pub  /home/user3/.ssh/id_rsa.pub

RUN chown user3:user3 /home/user3/.ssh/authorized_keys \
        /home/user3/.ssh/config \
        /home/user3/.ssh/id_rsa \
        /home/user3/.ssh/id_rsa.pub && \
    chmod 600 /home/user3/.ssh/authorized_keys \
              /home/user3/.ssh/config \
              /home/user3/.ssh/id_rsa && \
    chmod 644 /home/user3/.ssh/id_rsa.pub

RUN mkdir /var/run/sshd
CMD ["/usr/sbin/sshd", "-D"]
