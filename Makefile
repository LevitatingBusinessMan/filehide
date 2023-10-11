KDIR ?= /lib/modules/`uname -r`/build

obj-m += filehide.o

filehide:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
