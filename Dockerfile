FROM ubuntu:21.04

LABEL maintainer="Wenhao Jiang <whjiang1997@gmail.com>"

ENV PATH /usr/local/go/bin:$PATH

ENV GOLANG_VERSION 1.16

# install dependencies
RUN set -x && \ 
    apt-get update -qq && \
    apt-get install -y --no-install-recommends \
            wget \
            make \
            clang-12 \
            pkg-config \
            ca-certificates \
            ; \
            rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    update-alternatives --install \
    /usr/bin/clang clang /usr/bin/clang-12 1\
    --slave /usr/bin/clang++ clang++ /usr/bin/clang++-12 \
    ;

# install golang
RUN set -eux; \
    url='https://dl.google.com/go/go1.16.linux-amd64.tar.gz'; \
    wget -O go.tgz "$url" --progress=dot:giga;\
    tar -C /usr/local -xzf go.tgz; \
    rm go.tgz; \
    go version


WORKDIR /mnt

CMD [ "make" ]