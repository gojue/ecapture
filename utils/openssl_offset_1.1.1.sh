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
if [[ ! -f "${OPENSSL_DIR}/.git" ]]; then
  # skip cloning if the openssl directory already exists
  if [[ ! -d "${OPENSSL_DIR}" ]]; then
    git clone https://github.com/openssl/openssl.git ${OPENSSL_DIR}
  fi
fi

function run() {
  git fetch --tags
  cp -f ${PROJECT_ROOT_DIR}/utils/openssl_1_1_1_offset.c ${OPENSSL_DIR}/offset.c
  declare -A sslVerMap=()
  sslVerMap["a"]="a"

  sslVerMap["b"]="b"
  sslVerMap["c"]="b"

  sslVerMap["d"]="d"
  sslVerMap["e"]="d"
  sslVerMap["f"]="d"
  sslVerMap["g"]="d"
  sslVerMap["h"]="d"
  sslVerMap["i"]="d"

  sslVerMap["j"]="j"
  sslVerMap["k"]="j"
  sslVerMap["l"]="j"
  sslVerMap["m"]="j"
  sslVerMap["n"]="j"
  sslVerMap["o"]="j"
  sslVerMap["p"]="j"
  sslVerMap["q"]="j"
  sslVerMap["r"]="j"
  sslVerMap["s"]="j"
  sslVerMap["u"]="j"


#  exit 0
#  for ver in {a..r}; do
  # shellcheck disable=SC2068
  for ver in ${!sslVerMap[@]}; do
    tag="OpenSSL_1_1_1${ver}"
    val=${sslVerMap[$ver]}
    header_file="${OUTPUT_DIR}/openssl_1_1_1${val}_kern.c"
    header_define="OPENSSL_1_1_1_$(echo ${val} | tr "[:lower:]" "[:upper:]")_KERN_H"

    if [[ -f ${header_file} ]]; then
      echo "Skip ${header_file}"
      continue
    fi

    git checkout ${tag}
    echo "Generating ${header_file}"

    # config and make openssl/opensslconf.h
    ./config
    make include/openssl/opensslconf.h

    # set flag to include ssl/ssl_locl.h in OpenSSL_1_1_1{a..d}
    if [[ $ver == [a-d] ]]; then
      flags="-DSSL_LOCL_H"
    else
      unset flags
    fi
    clang ${flags} -I include/ -I . offset.c -o offset

    echo -e "#ifndef ECAPTURE_${header_define}" >${header_file}
    echo -e "#define ECAPTURE_${header_define}\n" >>${header_file}
    ./offset >>${header_file}
    echo -e "#include \"openssl.h\"" >>${header_file}
    echo -e "#include \"openssl_masterkey.h\"" >>${header_file}
    echo -e "\n#endif" >>${header_file}

    # clean up
    make clean

  done

  rm offset.c
}

pushd ${OPENSSL_DIR}
(run)
[[ "$?" != 0 ]] && popd
popd
