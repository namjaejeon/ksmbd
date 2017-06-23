obj-$(CONFIG_CIFS_SERVER) += cifssrv.o

cifssrv-y := 	export.o connect.o srv.o unicode.o encrypt.o auth.o \
		fh.o vfs.o misc.o smb1pdu.o smb1ops.o oplock.o netmisc.o \
		netlink.o

cifssrv-$(CONFIG_CIFS_SMB2_SERVER) += smb2pdu.o smb2ops.o asn1.o
