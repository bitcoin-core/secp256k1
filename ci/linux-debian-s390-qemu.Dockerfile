FROM debian

RUN dpkg --add-architecture s390x
RUN apt-get update
RUN apt-get install --no-install-recommends --no-upgrade -y make automake libtool
RUN apt-get install --no-install-recommends --no-upgrade -y gcc-s390x-linux-gnu libc6-dev-s390x-cross qemu-user libc6:s390x
