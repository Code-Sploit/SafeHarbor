obj-m += safeharbor.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/kernel modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/kernel clean
