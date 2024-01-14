FROM teeks99/clang-ubuntu:17

USER root

RUN apt update
RUN apt -y upgrade
RUN apt -y dist-upgrade
RUN apt -y autoremove

RUN apt -y install update-manager-core
RUN sed -i 's/Prompt=lts/Prompt=normal/' /etc/update-manager/release-upgrades
RUN DEBIAN_FRONTEND=noninteractive do-release-upgrade -f DistUpgradeViewNonInteractive

RUN apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends --no-install-suggests -o=Dpkg::Use-Pty=0 \
      binutils \
      wget \
      curl \
      ca-certificates \
      git

RUN apt-get -y install gcc-13
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 60

RUN apt-get -y install g++-13
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 60

RUN curl -fsSL https://xmake.io/shget.text | bash

ENV XMAKE_ROOT=y
