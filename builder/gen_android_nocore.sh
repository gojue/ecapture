#!/usr/bin/env bash
# bash builder/gen_android_nocore.sh 1.0.0
SHELL_GH=gh

# 发布Android nocore版本自用脚本。 ubnutu 20.04 ARM
UNAME_M=`uname -m`
OUTPUT_DIR="./bin"
SNAPSHOT_VERSION=v${1}
export PATH=/usr/local/go/bin:$PATH
ANDROID=1 make nocore
TAR_DIR=ecapture-android-${UNAME_M}_nocore-${SNAPSHOT_VERSION}

# ecapture-v0.4.8-android-x86_64.tar.gz
OUT_ARCHIVE=${OUTPUT_DIR}/ecapture-${SNAPSHOT_VERSION}-android-${UNAME_M}-nocore.tar.gz

# add gobin into $PATH
mkdir -p ${TAR_DIR}
cp LICENSE ${TAR_DIR}/LICENSE
cp CHANGELOG.md ${TAR_DIR}/CHANGELOG.md
cp README.md ${TAR_DIR}/README.md
cp README_CN.md ${TAR_DIR}/README_CN.md
cp ${OUTPUT_DIR}/ecapture ${TAR_DIR}/ecapture
tar  -czf ${OUT_ARCHIVE} ${TAR_DIR}


# upload to github
${SHELL_GH} release download ${SNAPSHOT_VERSION} -p "checksum-${SNAPSHOT_VERSION}.txt"
sha256sum ecapture-*.tar.gz >> checksum-${SNAPSHOT_VERSION}.txt
files=($(ls ecapture-*.tar.gz checksum-${SNAPSHOT_VERSION}.txt))
# shellcheck disable=SC2145
echo "-------------------upload files: ${files[@]} -------------------"
${SHELL_GH} release upload ${SNAPSHOT_VERSION} "${files[@]}" --clobber