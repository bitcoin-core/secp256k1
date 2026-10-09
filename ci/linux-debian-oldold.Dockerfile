FROM debian:oldoldstable-slim

SHELL ["/bin/bash", "-c"]

WORKDIR /root

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    git \
    autoconf automake libtool make \
    gcc \
    python3-full && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV VIRTUAL_ENV=/root/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN pip install lief
