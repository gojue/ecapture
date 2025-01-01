#!/usr/bin/env bash

# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"

echo "Welcome to eCapture project development environment initialization script."
echo "Home page: https://ecapture.cc"
echo "Github: https://github.com/gojue/ecapture"

# 环境检测
release_num=$(lsb_release -r --short)
if [ $? -ne 0 ]; then
  echo "command not found, supported ubuntu only."
  exit
fi

CLANG_NUM=-12
# shellcheck disable=SC2209
if [ ${release_num} == "20.04" ]; then
  CLANG_NUM=-9
  elif [ ${release_num} == "20.10" ]; then
  CLANG_NUM=-10
  elif [ ${release_num} == "21.04" ]; then
  CLANG_NUM=-11
  elif [ ${release_num} == "21.10" ]; then
  CLANG_NUM=-12
  elif [ ${release_num} == "22.04" ]; then
  CLANG_NUM=-12
  elif [ ${release_num} == "22.10" ]; then
  CLANG_NUM=-12
  elif [ ${release_num} == "23.04" ];then
  CLANG_NUM=-15
  elif [ ${release_num} == "23.10" ];then
    CLANG_NUM=-15
  elif [ ${release_num} == "24.04" ];then
  CLANG_NUM=-18
  else
    echo "used default CLANG Version"
    CLANG_NUM=
fi

echo "CLANG_NUM=${CLANG_NUM}"

UNAME_M=`uname -m`
ARCH="amd64"
CROSS_ARCH_PATH="arm64"
CROSS_COMPILE=aarch64-linux-gnu-
CROSS_COMPILE_DEB=gcc-aarch64-linux-gnu
if [[ ${UNAME_M} =~ "x86_64" ]];then
  ARCH="amd64"
  CROSS_ARCH_PATH="arm64"
  CROSS_COMPILE=aarch64-linux-gnu-
  CROSS_COMPILE_DEB=gcc-aarch64-linux-gnu
  elif [[ ${UNAME_M} =~ "aarch64" ]]; then
    ARCH="arm64"
    CROSS_ARCH_PATH="x86"
    CROSS_COMPILE=x86_64-linux-gnu-
    CROSS_COMPILE_DEB=gcc-x86-64-linux-gnu
    # 在ubuntu 24.04 上， 跨平台的GCC编译器的包名为“gcc-x86-64-linux-gnu”，不是以前的“x86_64-linux-gnu-gcc”
  else
    echo "unsupported arch ${UNAME_M}";
fi

GOBIN_ZIP="go1.22.10.linux-${ARCH}.tar.gz"
echo "GOBIN_ZIP:${GOBIN_ZIP}"


cd ~ || exit

uname -a
sudo apt-get update || { echo "apt-get update failed"; exit 1; }
# 环境安装，添加错误检查
sudo apt-get -y install build-essential pkgconf libelf-dev llvm${CLANG_NUM} \
    clang${CLANG_NUM} linux-tools-common linux-tools-generic ${CROSS_COMPILE_DEB} \
    libssl-dev flex bison bc linux-source || { echo "apt-get install failed"; exit 1; }
for tool in "clang" "llc" "llvm-strip"
do
  sudo rm -f /usr/bin/$tool
  sudo ln -s /usr/bin/$tool${CLANG_NUM} /usr/bin/$tool
done

cd /usr/src || exit
source_file=$(find . -maxdepth 1 -name "*linux-source*.tar.bz2")
source_dir=$(echo "$source_file" | sed 's/\.tar\.bz2//g')
sudo tar -xf $source_file
cd $source_dir || exit
test -f .config || yes "" | sudo make oldconfig
yes "" | sudo make ARCH=${CROSS_ARCH_PATH} CROSS_COMPILE=${CROSS_COMPILE} prepare V=0 > /dev/null
yes "" | sudo make prepare V=0 > /dev/null
ls -al $source_dir

clang --version
cd ~ || exit
# 安装golang，设置goproxy
wget https://golang.google.cn/dl/${GOBIN_ZIP}
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf ${GOBIN_ZIP}
export PATH=/usr/local/go/bin:$PATH
export GOPROXY=https://goproxy.cn

# clone 源码
git clone https://github.com/gojue/ecapture.git
cd ./ecapture || exit

echo "The development environment for the eCapture project has been successfully installed,"
echo "and you can start compiling the project now."
echo "see the README.md for more information."
echo "Enjoy it!"