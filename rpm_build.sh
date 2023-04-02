#!/bin/bash
rpmdev-setuptree
name=$(grep "Name:" rpmBuild.spec | awk '{print $2}')
version=$(grep "Version:" rpmBuild.spec | awk '{print $2}')
source0=$name-$version.tar.gz
tar zcvf ~/rpmbuild/SOURCES/$source0 ./
rpmbuild -bb rpmBuild.spec
