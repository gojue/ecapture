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
  git fetch --tags || echo "Warning: git fetch --tags failed (network issue?), continuing with existing tags"
  cp -f ${PROJECT_ROOT_DIR}/utils/boringssl-offset.c ${BORINGSSL_DIR}/offset.c
  declare -A sslVerMap=()
  sslVerMap["1"]="13" # android13-release
  sslVerMap["2"]="14" # android14-release
  sslVerMap["3"]="15" # android15-release
  sslVerMap["4"]="16" # android16-release

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
    echo "Android Version: ${val}, Generating ${header_file}"

    # The offset tool (boringssl-offset.c) uses C++17 type traits to auto-detect
    # which fields exist in this BoringSSL version and emits the appropriate
    # macros and feature flags directly.  No version-specific sed post-processing
    # is required here.
    g++ -std=c++17 -Wno-write-strings -Wno-invalid-offsetof \
        -I include/ -I . -I ./src/ offset.c -o offset

    {
      echo "#ifndef ECAPTURE_${header_define}"
      echo "#define ECAPTURE_${header_define}"
      echo ""
      ./offset
      echo "#include \"boringssl_const.h\""
      echo "#include \"boringssl_masterkey.h\""
      echo "#include \"openssl.h\""
      echo ""
      echo "#endif"
    } > "${header_file}"

  done

  rm offset.c
}

pushd ${BORINGSSL_DIR}
(run)
[[ "$?" != 0 ]] && popd
popd
