FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m user4 && chsh -s /bin/bash user4

RUN mkdir -p /home/user4/.ssh && \
    chown -R user4:user4 /home/user4/.ssh && \
    chmod 700 /home/user4/.ssh

COPY authorized_keys /home/user4/.ssh/authorized_keys
COPY data.json       /home/user4/data.json

RUN chown user4:user4 /home/user4/.ssh/authorized_keys \
                      /home/user4/data.json && \
    chmod 600 /home/user4/.ssh/authorized_keys

RUN mkdir /var/run/sshd
CMD ["/usr/sbin/sshd", "-D"]
