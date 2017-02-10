#!/bin/sh

modprobe libcrc32c
umount /mnt/ramdisk
umount /mnt/scratch
rmmod nd_pmem
modprobe nd_pmem readonly=1

rmmod nova
insmod nova.ko measure_timing=0 inplace_data_updates=0 replica_inode=1 replica_log=1 wprotect=1

sleep 1

mount -t NOVA -o init,wprotect /dev/pmem0 /mnt/ramdisk
mount -t NOVA -o init,wprotect /dev/pmem1 /mnt/scratch

