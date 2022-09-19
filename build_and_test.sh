#!/bin/sh
set -e

make -j4
make install
cd ../qemu
./qstart.sh
cd -
ctags -R .
#git status
