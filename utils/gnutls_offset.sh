#!/usr/bin/env bash
set -e

PROJECT_ROOT_DIR=$(pwd)
GNUTLS_DIR="${PROJECT_ROOT_DIR}/deps/gnutls"
OUTPUT_DIR="${PROJECT_ROOT_DIR}/kern"

if [[ ! -f "go.mod" ]]; then
  echo "Run the script from the project root directory"
  exit 1
fi

echo "check file exists: ${GNUTLS_DIR}/.git"
# skip cloning if the header file of the max supported version is already generated
if [[ ! -f "${GNUTLS_DIR}/.git" ]]; then
  echo "check directory exists: ${GNUTLS_DIR}"
  # skip cloning if the gnutls directory already exists
  if [[ ! -d "${GNUTLS_DIR}" ]]; then
    echo "git clone gnutls to ${GNUTLS_DIR}"
    git clone https://github.com/gnutls/gnutls.git ${GNUTLS_DIR}
  fi
fi


function run() {
  git fetch --tags
  cp -f ${PROJECT_ROOT_DIR}/utils/gnutls_offset.c ${GNUTLS_DIR}/offset.c
  main_version="3.8"

  for ver in $(seq 7 8); do
    tag="${main_version}.${ver}"
    underline_tag=$(echo $tag | tr "." "_")
    header_file="${OUTPUT_DIR}/gnutls_${underline_tag}_kern.c"
    header_define="GNUTLS_${underline_tag}_KERN_H"

    if [[ -f ${header_file} ]]; then
      echo "Skip ${header_file}"
      continue
    fi
    echo "git checkout ${tag}"
    git checkout ${tag}
    echo "Generating ${header_file}"

    # init
    ./bootstrap --skip-po --force --no-bootstrap-sync
    ./configure --without-p11-kit --without-brotli --without-zstd --without-zlib --without-tpm
    clang -I gnulib/lib/ -I lib/includes -I . offset.c -o offset

    echo -e "#ifndef ECAPTURE_${header_define}" >${header_file}
    echo -e "#define ECAPTURE_${header_define}\n" >>${header_file}
    ./offset >>${header_file}
    echo -e "\n#include \"gnutls.h\"" >>${header_file}
    echo -e "#include \"gnutls_masterkey.h\"" >>${header_file}
    echo -e "\n#endif" >>${header_file}

    # clean up
    make clean
  done

  rm offset.c
}

# install deps
sudo apt install -y \
  libtool \
  gettext \
  gperf \
  autopoint \
  gtk-doc-tools \
  nettle-dev \
  libev-dev \
  libtasn1-6-dev \
  libunistring-dev \
  libunbound-dev

pushd ${GNUTLS_DIR}
(run)
[[ "$?" != 0 ]] && popd
popd
