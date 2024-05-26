#!/usr/bin/env bash
set -e

PROJECT_ROOT_DIR=$(pwd)
# for non android boringssl , git repo : https://github.com/google/boringssl
BORINGSSL_REPO=https://github.com/google/boringssl.git
BORINGSSL_DIR="${PROJECT_ROOT_DIR}/deps/boringssl_non_android"
OUTPUT_DIR="${PROJECT_ROOT_DIR}/kern"

if [[ ! -f "go.mod" ]]; then
  echo "non-Android lib, Run the script from the project root directory"
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
  sslVerMap["0"]="master" # master
#  sslVerMap["1"]="fips-20220613" # fips-20220613
#  sslVerMap["2"]="fips-20210429" # android14-release

  # shellcheck disable=SC2068
  # shellcheck disable=SC2034
  for ver in ${!sslVerMap[@]}; do
    tag=${sslVerMap[$ver]}

    header_file="${OUTPUT_DIR}/boringssl_na_kern.c"
    header_define="BORINGSSL_NA_KERN_H"

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
