FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m user6 && chsh -s /bin/bash user6

RUN mkdir -p /home/user6/.ssh && \
    chown -R user6:user6 /home/user6/.ssh && \
    chmod 700 /home/user6/.ssh

COPY authorized_keys /home/user6/.ssh/authorized_keys
COPY data.json       /home/user6/data.json

RUN chown user6:user6 /home/user6/.ssh/authorized_keys \
                      /home/user6/data.json && \
    chmod 600 /home/user6/.ssh/authorized_keys

RUN mkdir /var/run/sshd
CMD ["/usr/sbin/sshd", "-D"]
