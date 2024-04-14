FROM ubuntu:22.04 as ecapture_builder

# Install Compilers
RUN apt-get update &&\
  apt-get install --yes build-essential pkgconf libelf-dev llvm-14 clang-14 linux-tools-common linux-tools-$(uname -r) make gcc flex bison file wget &&\
  # the for-shell built-in instruction does not count as a command 
  # and the shell used to execute the script is sh by default and not bash.
  rm -f /usr/bin/clang && ln -s /usr/bin/clang-14 /usr/bin/clang &&\
  rm -f /usr/bin/llc && ln -s /usr/bin/llc-14 /usr/bin/llc &&\
  rm -f /usr/bin/llvm-strip && ln -s /usr/bin/llvm-strip-14 /usr/bin/llvm-strip

# Install golang
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then \
  wget -O go.tar.gz https://golang.google.cn/dl/go1.22.2.linux-arm64.tar.gz; \
  elif [ "$TARGETARCH" = "amd64" ]; then \
  wget -O go.tar.gz https://golang.google.cn/dl/go1.22.2.linux-amd64.tar.gz; \
  else \
  echo "unsupport arch" && /bin/false ; \
  fi && \
  tar -C /usr/local -xzf go.tar.gz && \
  export PATH=$PATH:/usr/local/go/bin && \
  rm go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
RUN go env -w GOPROXY=https://goproxy.cn,direct

# Build ecapture
COPY ./ /build/ecapture
RUN cd /build/ecapture &&\
  make clean &&\
  make all -j $(nproc)
RUN cd /build/ecapture/lib/libpcap/ &&\
  make install

# ecapture release image
FROM alpine:latest as ecapture

COPY --from=ecapture_builder /build/ecapture/bin/ecapture /ecapture

ENTRYPOINT ["/ecapture"]
