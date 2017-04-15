#!/bin/sh

modprobe libcrc32c
umount /mnt/ramdisk
umount /mnt/scratch
rmmod nova
insmod nova.ko measure_timing=0 \
	inplace_data_updates=0 \
	wprotect=0 mmap_cow=1 \
	unsafe_metadata=1 \
	replica_metadata=1 metadata_csum=1 dram_struct_csum=1 \
	data_csum=1 data_parity=1

sleep 1

mount -t NOVA -o init /dev/pmem0 /mnt/ramdisk
mount -t NOVA -o init /dev/pmem1 /mnt/scratch

