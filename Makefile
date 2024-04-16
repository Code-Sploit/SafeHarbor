KERNEL_DIR := kernel
USER_DIR := user

.PHONY: all clean install deinstall

all:
	$(MAKE) -C $(KERNEL_DIR)
	$(MAKE) -C $(USER_DIR)

clean:
	$(MAKE) -C $(KERNEL_DIR) clean
	$(MAKE) -C $(USER_DIR) clean

install:
	$(MAKE) -C $(USER_DIR) install
	mkdir -p /usr/share/safeharbor
	cp $(KERNEL_DIR)/safeharbor.ko /usr/share/safeharbor

deinstall:
	$(MAKE) -C $(USER_DIR) deinstall
	rm -rf /usr/share/safeharbor
