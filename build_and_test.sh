#!/bin/sh
set -e

make
make install
cd ../qemu
./qstart.sh
cd -
ctags -R .
#git status
