#!/usr/bin/env bash
SHELL_GH=gh

# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ehids/ecapture/master/builder/gen_android_nocore.sh)"
sudo su
cd ~

# 环境安装
apt-get install --yes build-essential pkgconf libelf-dev llvm-9 clang-9 linux-tools-common linux-tools-generic
for tool in "clang" "llc" "llvm-strip"
do
  sudo rm -f /usr/bin/$tool
  sudo ln -s /usr/bin/$tool-9 /usr/bin/$tool
done

clang --version

# 安装gh命令
#type -p curl >/dev/null || sudo apt install curl -y
#curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
#&& sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
#&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
#&& sudo apt update \
#&& sudo apt install gh -y

# 安装golang，设置goproxy
wget https://golang.google.cn/dl/go1.18.8.linux-arm64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.8.linux-arm64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn

# clone 源码
git clone https://github.com/ehids/ecapture.git
cd ecapture


# 发布Android nocore版本自用脚本。 ubnutu 22.04 ARM
UNAME_M=`uname -m`
OUTPUT_DIR="./bin"
SNAPSHOT_VERSION=v${1}
ANDROID=1 make nocore
TAR_DIR=ecapture-android-${UNAME_M}_nocore-${SNAPSHOT_VERSION}

# bash build/gen_android_nocore.sh 1.0.0
# ecapture-v0.4.8-android-x86_64.tar.gz
OUT_ARCHIVE=${OUTPUT_DIR}/ecapture-${SNAPSHOT_VERSION}-android-${UNAME_M}-nocore.tar.gz
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