obj-$(CONFIG_CIFS_SERVER) += cifsd.o

cifsd-y := 	export.o unicode.o encrypt.o auth.o \
		fh.o vfs.o misc.o smb1pdu.o smb1ops.o oplock.o netmisc.o \
		netlink.o cifsacl.o \
		management/user.o\
		buffer_pool.o \
		transport_tcp.o \
		server.o

cifsd-$(CONFIG_CIFS_SMB2_SERVER) += smb2pdu.o smb2ops.o asn1.o
