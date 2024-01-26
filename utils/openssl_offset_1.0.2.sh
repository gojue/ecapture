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
echo "check file exists: ${OPENSSL_DIR}/.git"
if [[ ! -f "${OPENSSL_DIR}/.git" ]]; then
  # skip cloning if the openssl directory already exists
  echo "check directory exists: ${OPENSSL_DIR}"
  if [[ ! -d "${OPENSSL_DIR}" ]]; then
    echo "git clone openssl to ${OPENSSL_DIR}"
    git clone https://github.com/openssl/openssl.git ${OPENSSL_DIR}
  fi
fi

function run() {
  git fetch --tags
  cp -f ${PROJECT_ROOT_DIR}/utils/openssl_1_0_2_offset.c ${OPENSSL_DIR}/offset.c
  declare -A sslVerMap=()
#  sslVerMap[""]=""
  sslVerMap["a"]="a"

  sslVerMap["b"]="a"
  sslVerMap["c"]="a"

  sslVerMap["d"]="a"
  sslVerMap["e"]="a"
  sslVerMap["f"]="a"
  sslVerMap["g"]="a"
  sslVerMap["h"]="a"
  sslVerMap["i"]="a"

  sslVerMap["j"]="a"
  sslVerMap["k"]="a"
  sslVerMap["l"]="a"
  sslVerMap["m"]="a"
  sslVerMap["n"]="a"
  sslVerMap["o"]="a"
  sslVerMap["p"]="a"
  sslVerMap["q"]="a"
  sslVerMap["r"]="a"
  sslVerMap["s"]="a"
  sslVerMap["t"]="a"
  sslVerMap["u"]="a"


#  exit 0
#  for ver in {a..r}; do
  for ver in ${!sslVerMap[@]}; do
    tag="OpenSSL_1_0_2${ver}"
    val=${sslVerMap[$ver]}
    header_file="${OUTPUT_DIR}/openssl_1_0_2${val}_kern.c"
    header_define="OPENSSL_1_0_2_$(echo ${val} | tr "[:lower:]" "[:upper:]")_KERN_H"

    if [[ -f ${header_file} ]]; then
      echo "Skip ${header_file}"
      continue
    fi

    git checkout ${tag}
    echo "Generating ${header_file}"

    ./config

    clang -I include/ -I . offset.c -o offset $flag

    echo -e "#ifndef ECAPTURE_${header_define}" >${header_file}
    echo -e "#define ECAPTURE_${header_define}\n" >>${header_file}
    ./offset >>${header_file}
    echo -e "// openssl 1.0.2 does not support TLS 1.3, set 0 default" >>${header_file}
    echo -e "#define SSL_ST_HANDSHAKE_SECRET 0" >>${header_file}
    echo -e "#define SSL_ST_HANDSHAKE_TRAFFIC_HASH 0" >>${header_file}
    echo -e "#define SSL_ST_CLIENT_APP_TRAFFIC_SECRET 0" >>${header_file}
    echo -e "#define SSL_ST_SERVER_APP_TRAFFIC_SECRET 0" >>${header_file}
    echo -e "#define SSL_ST_EXPORTER_MASTER_SECRET 0\n" >>${header_file}
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
