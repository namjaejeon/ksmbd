================================================================================
* WHAT IS CIFSSRV?
================================================================================
CIFSSRV is an opensource In-kernel CIFS/SMB3 server created by Namjae Jeon for
Linux Kernel. It's an implementation of SMB/CIFS protocol in kernel space for
sharing files and IPC services over network. Initially the target is to provide
improved file I/O performances, but the bigger goal is to have some new features
which are much easier to develop and maintain inside the kernel and expose the
layers fully. Directions can be attributed to sections where SAMBA is moving to
few modules inside the kernel to have features like RDMA(Remote direct memory
access) to work with actual performance gain.

================================================================================
* Under PFIF
================================================================================
This code was developed in participation with the Protocol Freedom
Information Foundation.

Please see
  http://protocolfreedom.org/ and
  http://samba.org/samba/PFIF/
for more details.

================================================================================
* Git
================================================================================
The development git tree is available at
 - https://github.com/namjaejeon/cifssrv
 - https://github.com/namjaejeon/cifssrv-tools

================================================================================
* Bug Report or contribution for cifssrv development
================================================================================
For reporting bugs and sending patches, please send the patches to the following
mail address:
 - linkinjeont@gmail.com
 - namjae.jeon@samsung.com
 - namjae.jeon@protocolfreedom.org

================================================================================
* Features
===============================================================================
 - Implemented
   a. SMB1(CIFS), SMB2/3 protocols for basic file sharing
   b. Dynamic crediting
   c. Compound requests
   d. Durable handle
   e. oplock/lease
   f. Large MTU
   g. NTLM/NTLMv2
   h. Auto negotiation
   i. HMAC-SHA256 Signing
   j. Secure negotiate
   k. Signing Update

 - Planned
   a. SMB direct(RDMA)
   b. Multi-channel
   c. Preautentication integrity(SMB 3.1.1) (on-going)
   d. Durable handle v2
   e. Kerberos
   f. persistent handles
   g. directory lease
   h. SMB encryption

================================================================================
* DESIGN
================================================================================
 - Will update after redesigning cifssrv.

================================================================================
Configuration/Tools
================================================================================
 - Will update after redesigning cifssrv.

================================================================================
================================================================================

