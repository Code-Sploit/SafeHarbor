obj-m += safeharbor.o

safeharbor-objs := main.o helper.o log.o rule.o bridge.o filter.o spi.o dpi.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/kernel modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/kernel clean
