ifneq ($(KERNELRELEASE),)
# For kernel build
obj-$(CONFIG_CIFS_SERVER) += cifsd.o

cifsd-y :=	unicode.o encrypt.o auth.o vfs.o vfs_cache.o \
		misc.o oplock.o netmisc.o \
		mgmt/cifsd_ida.o mgmt/user_config.o mgmt/share_config.o \
		mgmt/tree_connect.o mgmt/user_session.o smb_common.o \
		buffer_pool.o transport_tcp.o transport_ipc.o server.o \
		connection.o crypto_ctx.o cifsd_work.o

cifsd-y +=	smb2pdu.o smb2ops.o smb2misc.o asn1.o smb1misc.o
cifsd-$(CONFIG_CIFS_INSECURE_SERVER) += smb1pdu.o smb1ops.o
else
# For external module build
EXTRA_FLAGS += -I$(PWD)
KDIR	?= /lib/modules/$(shell uname -r)/build
MDIR	?= /lib/modules/$(shell uname -r)
PWD	:= $(shell pwd)
PWD	:= $(shell pwd)

export CONFIG_CIFS_SERVER := m

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: cifsd.ko
	rm -f ${MDIR}/kernel/fs/cifsd/cifsd.ko
	install -m644 -b -D cifsd.ko ${MDIR}/kernel/fs/cifsd/cifsd.ko
	depmod -a

uninstall:
	rm -rf ${MDIR}/kernel/fs/cifsd
	depmod -a
endif

.PHONY : all clean install uninstall
