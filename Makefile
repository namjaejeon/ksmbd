obj-$(CONFIG_CIFS_SERVER) += cifsd.o

cifsd-y :=	unicode.o encrypt.o auth.o fh.o vfs.o misc.o \
		oplock.o netmisc.o \
		mgmt/cifsd_ida.o mgmt/user_config.o mgmt/share_config.o \
		mgmt/tree_connect.o mgmt/user_session.o smb_common.o \
		buffer_pool.o transport_tcp.o transport_ipc.o server.o

cifsd-y +=	smb2pdu.o smb2ops.o smb2misc.o asn1.o smb1misc.o
cifsd-$(CONFIG_CIFS_INSECURE_SERVER) += smb1pdu.o smb1ops.o
cifsd-$(CONFIG_CIFSD_ACL) += cifscal.o
