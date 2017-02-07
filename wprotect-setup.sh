#!/bin/sh

modprobe libcrc32c
umount /mnt/ramdisk
umount /mnt/scratch
rmmod nd_pmem
modprobe nd_pmem readonly=1

rmmod nova
insmod nova.ko measure_timing=0 inplace_data_updates=1 replica_inode=0 replica_log=0

sleep 1

mount -t NOVA -o init,wprotect /dev/pmem0 /mnt/ramdisk

