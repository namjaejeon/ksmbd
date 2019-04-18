
# Content

- [What is CIFSD?](#what-is-cifsd)
- [Under PFIF](#under-pfif)
- [Git](#git)
- [Maintainers](#maintainers)
- [Bug reports or contribution](#Bug-reports-or-contribution)
- [Features](#features)
- [Supported Linux Kernel Versions](#supported-linux-kernel-versions)
- [CIFSD architecture](#cifsd-architecture)


## What is CIFSD?

CIFSD is an opensource In-kernel CIFS/SMB3 server created by Namjae Jeon for Linux Kernel. It's an implementation of SMB/CIFS protocol in kernel space for sharing files and IPC services over network. Initially the target is to provide improved file I/O performances, but the bigger goal is to have some new features which are much easier to develop and maintain inside the kernel and expose the layers fully. Directions can be attributed to sections where SAMBA is moving to few modules inside the kernel to have features like RDMA(Remote direct memory access) to work with actual performance gain.


## Under PFIF

This code was developed in participation with the Protocol Freedom Information Foundation.

Please see
* http://protocolfreedom.org/
* http://samba.org/samba/PFIF/
for more details.


## Git

The development git tree is available at
* https://github.com/namjaejeon/cifsd
* https://github.com/namjaejeon/cifsd-tools


## Maintainers

* Namjae Jeon <linkinjeon@gmail.com>
* Sergey Senozhatsky <sergey.senozhatsky@gmail.com>


## Bug reports or contribution

For reporting bugs and sending patches, please send the patches to the following mail address:

* linux-cifsd-devel@lists.sourceforge.net
* linkinjeon@gmail.com
* sergey.senozhatsky@gmail.com

or open issues/send PRs to [CIFSD](https://github.com/cifsd-team/cifsd).

## Features

*Implemented*
1. SMB1(CIFS), SMB2/3 protocols for basic file sharing
2. Dynamic crediting
3. Compound requests
4. Durable handle
5. oplock/lease
6. Large MTU
7. NTLM/NTLMv2
8. Auto negotiation
9. HMAC-SHA256 Signing
10. Secure negotiate
11. Signing Update
12. Preautentication integrity(SMB 3.1.1)
13. SMB3 encryption

*Planned*
1. SMB direct(RDMA)
2. Multi-channel
3. Durable handle v2
4. Kerberos
5. Persistent handles
6. Directory lease


## Supported Linux Kernel Versions

* Linux Kernel 4.1 or later


## CIFSD architecture

```
               |--- ...
       --------|--- kcifsd/3 - Client 3
       |-------|--- kcifsd/2 - Client 2
       |       |         _____________________________________________________
       |       |        |- Client 1                                           |
<--- Socket ---|--- kcifsd/1   <<= Authentication : NTLM/NTLM2, Kerberos(TODO)|
       |       |      | |      <<= SMB : SMB1, SMB2, SMB2.1, SMB3, SMB3.0.2,  |
       |       |      | |                SMB3.1.1                             |
       |       |      | |_____________________________________________________|
       |       |      |
       |       |      |--- VFS --- Local Filesystem
       |       |
KERNEL |--- kcifsd/0(forker kthread)
---------------||---------------------------------------------------------------
USER           ||
               || communication using NETLINK
               ||  ______________________________________________
               || |                                              |
             cifsd   <<= DCE/RPC, WINREG                         |
               ^  |  <<= configure shares setting, user accounts |
               |  |______________________________________________|
               |
               |------ smb.conf(config file)
               |
               |------ cifspwd.db(user account/password file)
                            ^
  cifsadmin ----------------|

```
