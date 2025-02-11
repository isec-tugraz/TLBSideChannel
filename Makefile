obj-m = lkm.o
KVERSION = $(shell uname -r)
all: build modules remove insert
init: build modules insert
remove:
	sudo rmmod lkm
insert:
	sudo insmod lkm.ko && sudo chmod 666 /dev/lkm
modules:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	make -C generic clean
	make -C heap clean
	make -C stack clean
	make -C page-table clean
	make -C attacks clean
build:
	make -C generic
	make -C heap
	make -C stack
	make -C page-table
	make -C attacks
