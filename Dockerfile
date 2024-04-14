FROM ubuntu:22.04 as ecapture_builder

# Install Compilers
RUN apt-get update &&\
  apt-get install --yes build-essential pkgconf libelf-dev llvm-14 clang-14 linux-tools-common linux-tools-generic make git gcc flex bison file 
# the for-shell built-in instruction does not count as a command 
# and the shell used to execute the script is sh by default and not bash.
CMD /bin/bash -c for tool in "clang" "llc" "llvm-strip"; \
  do \
  rm -f /usr/bin/$tool \
  ln -s /usr/bin/$tool-14 /usr/bin/$tool \
  done

# Install golang
ARG TARGETARCH
RUN echo ${TARGETARCH} &&\
  apt-get install -y wget
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
RUN cd /build/ecapture/lib/libpcap/ && make install&&\
  cd /build/ecapture &&\
  make clean &&\
  make all -j $(nproc)

# ecapture release image
FROM alpine:latest as ecapture

COPY --from=ecapture_builder /build/ecapture/bin/ecapture /ecapture

ENTRYPOINT ["/ecapture"]