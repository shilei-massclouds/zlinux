#!/bin/sh

./clr.sh

dd if=/dev/zero of=./rootfs.ext2 bs=1M count=32
mkfs.ext2 ./rootfs.ext2
mkdir fs
sudo mount -o loop rootfs.ext2 ./fs/
sudo mkdir fs/sbin
sudo mkdir fs/etc
riscv64-linux-gnu-gcc -o ./init init.c
sudo cp ./init ./fs/sbin/
sudo umount ./fs
cp ./rootfs.ext2 ~/gitStudy/qemu/image/test.raw
