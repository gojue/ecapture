#!/usr/bin/env bash
set -e

PROJECT_ROOT_DIR=$(pwd)
OPENSSL_DIR="${PROJECT_ROOT_DIR}/deps/openssl"
OUTPUT_DIR="${PROJECT_ROOT_DIR}/kern"

if [[ ! -f "go.mod" ]]; then
  echo "Run the script from the project root directory"
  exit 1
fi

# skip cloning if the header file of the max supported version is already generated
if [[ ! -f "${OUTPUT_DIR}/openssl_3_0_0_kern.c" ]]; then
  # skip cloning if the openssl directory already exists
  if [[ ! -d "${OPENSSL_DIR}" ]]; then
    git clone https://github.com/openssl/openssl.git ${OPENSSL_DIR}
  fi
fi

function run() {
  git fetch --tags
  cp -f ${PROJECT_ROOT_DIR}/utils/openssl_3_0_offset.c ${OPENSSL_DIR}/offset.c

  for ver in {0..6}; do
    tag="openssl-3.0.${ver}"
    header_file="${OUTPUT_DIR}/openssl_3_0_${ver}_kern.c"
    header_define="OPENSSL_3_0_$(echo ${ver} | tr "[:lower:]" "[:upper:]")_KERN_H"

    if [[ -f ${header_file} ]]; then
      echo "Skip ${header_file}"
      continue
    fi

    git checkout ${tag}
    echo "Generating ${header_file}"


    # config and make openssl/opensslconf.h
    ./config

#    make reconfigure reconf
    make include/openssl/opensslconf.h
    make include/openssl/configuration.h
    make build_generated

    # set flag to include ssl/ssl_locl.h in openssl-3.0{0..6}

    clang -I include/ -I . offset.c -o offset $flag

    echo -e "#ifndef ECAPTURE_${header_define}" >${header_file}
    echo -e "#define ECAPTURE_${header_define}\n" >>${header_file}
    ./offset >>${header_file}
    echo -e "#include \"openssl.h\"" >>${header_file}
    echo -e "#include \"openssl_masterkey_3.0.h\"" >>${header_file}
    echo -e "\n#endif\n" >>${header_file}

    # clean up
    make clean

  done

  rm offset.c
}

pushd ${OPENSSL_DIR}
(run)
[[ "$?" != 0 ]] && popd
popd
