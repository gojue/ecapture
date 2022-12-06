#!/usr/bin/env bash
set -e

PROJECT_ROOT_DIR=$(pwd)
BORINGSSL_DIR="${PROJECT_ROOT_DIR}/deps/boringssl"
OUTPUT_DIR="${PROJECT_ROOT_DIR}/kern"

if [[ ! -f "go.mod" ]]; then
  echo "Run the script from the project root directory"
  exit 1
fi

# skip cloning if the header file of the max supported version is already generated
if [[ ! -f "${OUTPUT_DIR}/boringssl_1_1_1_kern.c" ]]; then
  # skip cloning if the openssl directory already exists
  if [[ ! -d "${BORINGSSL_DIR}" ]]; then
    git clone https://github.com/google/boringssl.git ${BORINGSSL_DIR}
  fi
fi

function run() {
  git fetch --tags
  cp -f ${PROJECT_ROOT_DIR}/utils/boringssl-offset.c ${BORINGSSL_DIR}/offset.c
  declare -A sslVerMap=()
  sslVerMap["0"]="0"

  # shellcheck disable=SC2068
  for ver in ${!sslVerMap[@]}; do
#    tag="openssl-3.0.${ver}"
#    val=${sslVerMap[$ver]}
    header_file="${OUTPUT_DIR}/boringssl_1_1_1_kern.c"
    header_define="BORINGSSL_1_1_1_KERN_H"

    if [[ -f ${header_file} ]]; then
      echo "Skip ${header_file}"
      continue
    fi

#    git checkout ${tag}
    echo "Generating ${header_file}"

    cmake .

    g++ -I include/ -I . offset.c -o offset

    echo -e "#ifndef ECAPTURE_${header_define}" >${header_file}
    echo -e "#define ECAPTURE_${header_define}\n" >>${header_file}
    ./offset >>${header_file}
    echo -e "#include \"boringssl_const.h\"" >>${header_file}
    echo -e "#include \"openssl.h\"" >>${header_file}
    echo -e "#include \"boringssl_masterkey.h\"" >>${header_file}
    echo -e "\n#endif\n" >>${header_file}

    # clean up
    make clean

  done

  rm offset.c
}

pushd ${BORINGSSL_DIR}
(run)
[[ "$?" != 0 ]] && popd
popd
