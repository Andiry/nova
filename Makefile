#
# Makefile for the linux NOVA filesystem routines.
#

obj-m += nova.o

nova-y := balloc.o bbuild.o dax.o dir.o file.o gc.o inode.o ioctl.o journal.o log.o\
	  namei.o rebuild.o stats.o super.o symlink.o procfs.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
