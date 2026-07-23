FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sshpass nmap ncat curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m user4 && chsh -s /bin/bash user4

RUN mkdir -p /home/user4/.ssh && \
    chown -R user4:user4 /home/user4/.ssh && \
    chmod 700 /home/user4/.ssh

COPY authorized_keys /home/user4/.ssh/authorized_keys
COPY ssh/config      /home/user4/.ssh/config
COPY ssh/id_rsa      /home/user4/.ssh/id_rsa
COPY ssh/id_rsa.pub  /home/user4/.ssh/id_rsa.pub

RUN chown user4:user4 /home/user4/.ssh/authorized_keys \
        /home/user4/.ssh/config \
        /home/user4/.ssh/id_rsa \
        /home/user4/.ssh/id_rsa.pub && \
    chmod 600 /home/user4/.ssh/authorized_keys \
              /home/user4/.ssh/config \
              /home/user4/.ssh/id_rsa && \
    chmod 644 /home/user4/.ssh/id_rsa.pub

RUN mkdir /var/run/sshd
CMD ["/usr/sbin/sshd", "-D"]
