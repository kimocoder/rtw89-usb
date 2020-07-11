# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

CONFIG_RTW89_CORE=m
CONFIG_RTW89_PCI=m
CONFIG_RTW89_USB=m

obj-$(CONFIG_RTW89_CORE) += rtw89_core.o
rtw89_core-y += core.o \
		mac80211.o \
		mac.o \
		fw.o \
		phy.o \
		rtw8852a.o \
		rtw8852a_table.o \
		efuse.o \
		debug.o

obj-$(CONFIG_RTW89_PCI) += rtw89_pci.o
obj-$(CONFIG_RTW89_USB) += rtw89_usb.o
rtw89_pci-y := pci.o
rtw89_usb-y := usb.o

######################## section below is internal only #######################

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       ?= $(shell pwd)
SUBARCH   := $(shell uname -m | sed -e s/i.86/i386/)
ARCH      ?= $(SUBARCH)

all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNELDIR) M=$(PWD) C=2

cscope:
	find ./ -name "*.[ch]" > cscope.files
	cscope -Rbq -i cscope.files
	ctags -R --exclude=.git

.PHONY: clean

clean:
	rm -f *.o .*.d *.a *.ko .*.cmd *.mod* *.order *.symvers *.tmp_versions

