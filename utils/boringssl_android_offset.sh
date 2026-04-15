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
  declare -A sslVerMap=()
  # get all commit about ssl/internel.h  who commit date > Apr 25 23:00:0 2021  (android 12 release)
  # see https://android.googlesource.com/platform/external/boringssl/+/refs/heads/android12-release .
  # range commit id from 160e1757ccacbde7488b145070eca94f2c370de2
  # this repo is different from https://boringssl.googlesource.com/boringssl
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

    # In Android 16+, BoringSSL changed TLS 1.3 secret fields from raw arrays
    # to InplaceVector, removed ssl_st.version and ssl_session_st.secret_length,
    # and added ssl_session_st.ssl_version.  Use a dedicated offset source file.
    if (( val > 15 )); then
        echo "Android version ${val} greater than 15, using boringssl-android16-offset.c"
        cp -f ${PROJECT_ROOT_DIR}/utils/boringssl-android16-offset.c ${BORINGSSL_DIR}/offset.c
    else
        cp -f ${PROJECT_ROOT_DIR}/utils/boringssl-offset.c ${BORINGSSL_DIR}/offset.c
    fi
    g++ -Wno-write-strings -Wno-invalid-offsetof -I include/ -I . -I ./src/ offset.c -o offset

    echo -e "#ifndef ECAPTURE_${header_define}" >${header_file}
    echo -e "#define ECAPTURE_${header_define}\n" >>${header_file}
    ./offset >>${header_file}

    # Android 16+ dropped secret_length from ssl_session_st; use 0xFF sentinel
    # so boringssl_masterkey.h uses a fixed length instead of reading the field.
    if (( val > 15 )); then
        echo -e "#define SSL_SESSION_ST_SECRET_LENGTH 0xFF\n" >>${header_file}
        # Android 16+ uses InplaceVector for TLS 1.3 secrets; enable the
        # BORINGSSL_INPLACEVECTOR_SECRETS path in boringssl_const.h so that
        # the pre-computed offsets above are used directly.
        echo -e "#define BORINGSSL_INPLACEVECTOR_SECRETS\n" >>${header_file}
        # InplaceVector size_ field is at data_offset + SSL_MAX_MD_SIZE (48).
        # For hash_len, read from secret.size_ at BSSL__SSL_HANDSHAKE_SECRET + 48.
        echo -e "#define BSSL__SSL_HANDSHAKE_HASH_LEN (BSSL__SSL_HANDSHAKE_SECRET+0x30)\n" >>${header_file}
    fi

    echo -e "#include \"boringssl_const.h\"" >>${header_file}
    echo -e "#include \"boringssl_masterkey.h\"" >>${header_file}
    echo -e "#include \"openssl.h\"" >>${header_file}
    echo -e "\n#endif" >>${header_file}

  done

  rm -f offset.c offset
}

pushd ${BORINGSSL_DIR}
(run)
[[ "$?" != 0 ]] && popd
popd
