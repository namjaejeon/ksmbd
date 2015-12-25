================================================================================
WHAT IS CIFSSRV?
================================================================================
CIFSSRV is implementation of SMB/CIFS protocol in kernel space for sharing files
and IPC services over network, will be termed as In-Kernel SMB Server. Initially
the target is to provide improved file I/O performances, but the bigger goal is
to have some new features which are much easier to develop and maintain inside
the kernel and expose the layers fully. Directions can be attributed to sections
where SAMBA is moving to few modules inside the kernel to have features like
RDMA(or Remote direct memory access) to work with actual performance gain.

Please see
  http://protocolfreedom.org/ and
  http://samba.org/samba/PFIF/
for more details.

The development git tree is available at https://github.com/namjaejeon/cifssrv
-----------

For reporting bugs and sending patches, please use the following mailing list:
>>>>>

================================================================================
DESIGN
================================================================================
CIFSSRV is based on TCP/IP communication, so will not be suited to work with
clients which are still using NetBIOS for connection.
Main forker thread which is responsible for accepting connection is listening on
destined port 445 as per the SMB specification.
Corresponding to each connection request, the server part will create a separate
thread per client connection called "cifssrvd/x>, where 'x' denotes
the numbering for client connections.
While the forker thread will continue run in background.
cifssrv/d will come into prominence once there is an established connection.
At initialization of each thread (represented by "tcp_server_info" ) -
few initializations are done keeping in mind the per client (varying SMB
versoins) behaviour most important the File id management bitmap is initialized
(described later).
	
This thread loops over the ephemeral connection from 445 to receives the SMB Requests from clients.

		       /-> Receive/ParsePDU->\															 
|---------|       /-- [cifssrvd/1]/                                    \ <---> Queue the SMB Work item for kworker <--> [kworker/0:0] <--> Invoke handler as per SMB version commands
|         |      /                   \		           /
|         |     /	       \-> Prepare/Send PDU<-/
|Forker|-->/----- [cifssrvd/2]
|         |    \
|---------|     \---- [cifssrvd/3]

FID Management
Main part of controlling the operations as the information is stored and
retrieved using this part. The allocation routine for the bitmap area follows
the approach from VFS, and to start with only space is reserved for the '32'
descriptors - which is extended based on the future open requirement

Main Structures
struct fidtable_desc {
        spinlock_t fidtable_lock;
        struct fidtable *ftab;
};

struct fidtable {
        unsigned int max_fids;
        struct cifssrv_file **fileid;      /* cifssrv_file array */
        unsigned int start_pos;
        unsigned long *cifssrv_bitmap;
};

FIDTABLE is the place holder for all the file handleres.
Each FILE handle is represented by "cifssrv_file", so each open
file/directory will have corresponding this instance on server.

struct cifssrv_file {
        struct file *filp;
        /* if ls is happening on directory, below is valid*/
        struct smb_readdir_data readdir_data;
        int             dirent_offset;
        int             search_over;
        /* oplock info */
        struct ofile_info *ofile;
        bool delete_on_close;
        bool is_durable;
        uint64_t persistent_id;
}; 

Each file handle is represented by "struct file" in linux, for CIFSSRV,
this reference is stored in corresponding "cifssrv_file".
In addition to this - the corresponding, oplock/durable information is
also stored in this. So, from SMB Requests - where in FID is part of
the request, which becomes a "value" to be searched in the bitmap to locate
the "cifssrv_file" instance and then correspondingly "filp" can be
obtained to perform VFS specific file operations.

================================================================================
Compilation
================================================================================
1) Compilation
================================================================================
Configuration/Tools
================================================================================
As part of the configuring the Server and managing - there are corresponding
user utils provided as part of the CIFSSRV package.

User level helpers are the user space tools for CIFSSRV server which allows.
1. Add/delete users, shares.
2. Set the configuration of Shares.
3. Get the statistics of CIFSSRV server.

The format for configuring CIFSSRV server aligns with SAMBA, so that users 
who are accustomed to SAMBA, can easily switch to CIFSSRV.

There are two main component of User level helpers 
1. CIFSManager: 
	For management of User accounts and share configuration
		a. For Add/delete users, shares
		b. Setting the properties of Shares.
		c. Query on User accounts.
		d. Import user accounts from SAMBA database.
		e. Listing of shares.
		f. Show share and share parameters.
	Usage Arguments:
			"	-h help\n"
			"	-v verbose\n"
			"	-a <usrname> add/update user\n"
			"	-r <usrname> remove user\n"
			"	-q <usrname> query user exists in cifssrv\n"
			"	-i <path> import userlist from SAMBA database\n"
			"	-c configure cifssrv with user(s)  and share(s)  details\n"
			"	-l list all shares\n"
			"	-s <share> show share settings\n");

2. CIFSstat: 
	To get the CIFSSRV server stats like:
		a. Uptime of the server
		b. Number of shares.
		c. Type of connection i.e. SMB1/SMB2.0/SMB2.1/SMB3.0 (Dialects)
		d. Number of open files
		e. Number of outstanding requests.
		f. Total requests served.
		g. Avg duration per request(in debug mode).
		h. Max. Duration of request(in debug mode).
	Usage Arguments:
			"	-h help\n"
			"	-s show server stat\n"
			"	-c <client IP> show client stat\n");
================================================================================
================================================================================

