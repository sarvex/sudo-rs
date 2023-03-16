FROM debian:buster-slim
# we use sshpass to test password authentication via TTY emulation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sudo \
    sshpass
