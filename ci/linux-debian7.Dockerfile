FROM docker.io/debian/eol:wheezy

SHELL ["/bin/bash", "-c"]

WORKDIR /root

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    git \
    autoconf automake libtool make \
    gcc && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
