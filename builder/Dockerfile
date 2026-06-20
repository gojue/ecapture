FROM ubuntu:22.04 as ecapture_builder

# Install compilers and tools
RUN apt-get update &&\
  apt-get install --yes git build-essential pkgconf libelf-dev llvm-14 clang-14 linux-tools-common make gcc flex bison file wget linux-source &&\
  rm -f /usr/bin/clang && ln -s /usr/bin/clang-14 /usr/bin/clang &&\
  rm -f /usr/bin/llc && ln -s /usr/bin/llc-14 /usr/bin/llc &&\
  rm -f /usr/bin/llvm-strip && ln -s /usr/bin/llvm-strip-14 /usr/bin/llvm-strip

# Prepare stable kernel headers from linux-source for reproducible noncore eBPF bytecode.
# Avoids depending on linux-headers-$(uname -r) which varies with the CI runner's kernel.
RUN cd /usr/src &&\
  source_file=\$(find . -maxdepth 1 -name "*linux-source*.tar.bz2") &&\
  source_dir=\$(echo "\$source_file" | sed 's/\.tar\.bz2//g') &&\
  tar -xf "\$source_file" &&\
  cd "\$source_dir" &&\
  test -f .config || make oldconfig &&\
  make prepare V=0 &&\
  ln -sf "\$source_dir" /usr/src/linux-headers-ecapture

# Install golang
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ] || [ "$TARGETARCH" = "amd64" ]; then\
  wget -O go.tar.gz https://golang.google.cn/dl/go1.24.6.linux-${TARGETARCH}.tar.gz; \
  else \
  echo "unsupport arch" && /bin/false ; \
  fi && \
  tar -C /usr/local -xzf go.tar.gz && \
  export PATH=$PATH:/usr/local/go/bin && \
  rm go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

# Build ecapture
COPY ./ /build/ecapture

ARG VERSION

RUN cd /build/ecapture &&\
  make clean &&\
  KERN_HEADERS=/usr/src/linux-headers-ecapture make all SNAPSHOT_VERSION=${VERSION}_docker

# ecapture release image
FROM alpine:latest as ecapture

COPY --from=ecapture_builder /build/ecapture/bin/ecapture /ecapture

ENTRYPOINT ["/ecapture"]