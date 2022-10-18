#!/usr/bin/env bash

# shellcheck disable=SC2164
cd ~
git clone https://github.com/openssl/openssl.git
git checkout -b OpenSSL_1_1_1-stable origin/OpenSSL_1_1_1-stable
# create include/openssl/opensslconf.h
./config
make

# cp openssl_1.1.1_offset.c to openssl directory.
cp openssl_offset.c ~/openssl/
# create offset.h
# in OpenSSL_1_1_1* , tag a to d, use ssl/ssl_locl.h ,not ssl/ssl_local.h .
# so ,need to modify filename by yourself.
#for tag in "e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q"
for tag in "a" "b" "c" "d"
do
git checkout OpenSSL_1_1_1$tag
date
tag_name=`git describe --tags --abbrev=0`
echo $tag_name
clang -I include/ -I . offset.c -o openssl_offset
./openssl_offset > $tag_name.h
done