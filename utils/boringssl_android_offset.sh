#!/usr/bin/env bash
set -e

PROJECT_ROOT_DIR=$(pwd)
BORINGSSL_REPO=https://android.googlesource.com/platform/external/boringssl
BORINGSSL_DIR="${PROJECT_ROOT_DIR}/deps/boringssl"
OUTPUT_DIR="${PROJECT_ROOT_DIR}/kern"

if [[ ! -f "go.mod" ]]; then
  echo "Run the script from the project root directory"
  exit 1
fi

# skip cloning if the header file of the max supported version is already generated
if [[ ! -d "${BORINGSSL_DIR}/.git" ]]; then
  # skip cloning if the openssl directory already exists
  if [[ ! -d "${BORINGSSL_DIR}" ]]; then
    git clone ${BORINGSSL_REPO} ${BORINGSSL_DIR}
  fi
fi

function run() {
  git fetch --tags
  cp -f ${PROJECT_ROOT_DIR}/utils/boringssl-offset.c ${BORINGSSL_DIR}/offset.c
  declare -A sslVerMap=()
  # get all commit about ssl/internel.h  who commit date > Apr 25 23:00:0 2021  (android 12 release)
  # see https://android.googlesource.com/platform/external/boringssl/+/refs/heads/android12-release .
  # range commit id from 160e1757ccacbde7488b145070eca94f2c370de2
  # this repo is different from https://boringssl.googlesource.com/boringssl
  sslVerMap["1"]="13" # android13-release
  sslVerMap["2"]="14" # android14-release

  # shellcheck disable=SC2068
  # shellcheck disable=SC2034
  for ver in ${!sslVerMap[@]}; do
    val=${sslVerMap[$ver]}
    tag="android${val}-release"

    header_file="${OUTPUT_DIR}/boringssl_a_${val}_kern.c"
    header_define="BORINGSSL_A_${val}_KERN_H"

    if [[ -f ${header_file} ]]; then
      echo "Skip ${header_file}"
      continue
    fi
    git checkout ${tag}
    echo "Generating ${header_file}"

    g++ -Wno-write-strings -Wno-invalid-offsetof -I include/ -I . -I ./src/ offset.c -o offset

    echo -e "#ifndef ECAPTURE_${header_define}" >${header_file}
    echo -e "#define ECAPTURE_${header_define}\n" >>${header_file}
    ./offset >>${header_file}
    echo -e "#include \"boringssl_const.h\"" >>${header_file}
    echo -e "#include \"boringssl_masterkey.h\"" >>${header_file}
    echo -e "#include \"openssl.h\"" >>${header_file}
    echo -e "\n#endif" >>${header_file}

  done

  rm offset.c
}

pushd ${BORINGSSL_DIR}
(run)
[[ "$?" != 0 ]] && popd
popd
