#!/bin/sh

echo "Unmount existing partition..."
umount /mnt/ramdisk
umount /mnt/scratch
rmmod nova
insmod nova.ko measure_timing=0 inplace_data_updates=1 replica_metadata=1 metadata_csum=1 unsafe_metadata=1 \
			wprotect=0 mmap_cow=1 data_csum=1 data_parity=1 dram_struct_csum=1

echo "Unmount done."
sleep 1

echo "Mounting..."
mount -t NOVA /dev/pmem0 /mnt/ramdisk

