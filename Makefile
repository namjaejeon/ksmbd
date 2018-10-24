obj-$(CONFIG_CIFS_SERVER) += cifsd.o

cifsd-y := 	unicode.o encrypt.o auth.o fh.o vfs.o misc.o smb1pdu.o \
		smb1ops.o oplock.o netmisc.o smb1misc.o cifsacl.o \
		mgmt/cifsd_ida.o mgmt/user_config.o mgmt/share_config.o \
		mgmt/tree_connect.o mgmt/user_session.o smb_common.o \
		buffer_pool.o transport_tcp.o transport_ipc.o server.o

cifsd-$(CONFIG_CIFS_SMB2_SERVER) += smb2pdu.o smb2ops.o smb2misc.o asn1.o
