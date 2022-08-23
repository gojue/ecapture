#!/usr/bin/env bash

# 发布Android nocore版本自用脚本。 ubnutu 22.04 ARM
UNAME_M=`uname -m`
OUTPUT_DIR="./bin"
SNAPSHOT_VERSION=v${1}
ANDROID=1 make nocore
TAR_DIR=ecapture-android-${UNAME_M}_nocore-${SNAPSHOT_VERSION}

# bash build/gen_android_nocore.sh 1.0.0
OUT_ARCHIVE=${OUTPUT_DIR}/ecapture-android-${UNAME_M}_nocore-${SNAPSHOT_VERSION}.tar.gz
mkdir -p ${TAR_DIR}
cp LICENSE ${TAR_DIR}/LICENSE
cp CHANGELOG.md ${TAR_DIR}/CHANGELOG.md
cp README.md ${TAR_DIR}/README.md
cp README_CN.md ${TAR_DIR}/README_CN.md
cp ${OUTPUT_DIR}/ecapture ${TAR_DIR}/ecapture
tar  -czf ${OUT_ARCHIVE} ${TAR_DIR}


# upload to github
gh release download ${SNAPSHOT_VERSION} -p "checksum-${SNAPSHOT_VERSION}.txt"
sha256sum ecapture-*.tar.gz >> checksum-${SNAPSHOT_VERSION}.txt
files=($(ls ecapture-*.tar.gz checksum-${SNAPSHOT_VERSION}.txt))
# shellcheck disable=SC2145
echo "-------------------upload files: ${files[@]} -------------------"
gh release upload ${SNAPSHOT_VERSION} "${files[@]}" --clobber