posixovl — The POSIX Overlay Filesystem
=======================================

Syntax
------

       mount.posixovl [-FH] [-S source_dir] target_dir [-- fuse_opts]

Description
-----------

       posixovl  provides a filesystem view that supports various POSIX opera‐
       tions while using an otherwise incapable lower filesystem.  Filesystems
       of  various  degrees  of  POSIXness  can be utilitzed. VFAT is a common
       denominator when it comes to cross-compatibility,  though  NTFS  —  its
       features  are unused in Linux — would be another possibility. Secondly,
       potent native POSIX-style filesystems can  also  be  used,  though  the
       actual use of doing that remains to be discovered.

Options
-------

       If  no  source  directory is given, the target directory specifies both
       source and target (mountpoint), yielding an "overmount".

       -F     Disable permission and ownership checks on the lower filesystem.
              Normally  these  would  be  used  to check for POSIX filesystems
              mounted inside a non-POSIX tree. (For example,  where  /vfat  is
              vfat, and /vfat/xfs is a POSIX-behaving filesystem.)

       -H     When  this  option  is  enabled  and  a hardlink in the posixovl
              namespace is created, the contents of the file  will  be  repli‐
              cated  in  the  lower  filesystem  rather  than using zero-sized
              placeholder files. Note that the replicas will  not  be  updated
              later on when editing the inode through posixovl.

Supported operations
--------------------

       posixovl  will  emulate  the following calls if the lower filesystem is
       incapable of supporting these operations:

       ·   chmod

       ·   chown

       ·   hard links

       ·   mkfifo

       ·   mknod

       ·   symbolic links

       The following currently only work in passthrough  mode  (when  using  a
       lower filesystem that already supports these):

       ·   Linux ACLs/xattrs

       Missing suppot:

       ·   Case-sensitivity

Notes
-----

       Using  posixovl  on  an  already  POSIX-behaving  filesystem (e.g. XFS)
       incurs some issues, since detecting whether a path is POSIX behaving or
       not is difficult.  Hence, the following decision was made:

       ·   permissions  will  be  set  to  the default permissions (see below)
           unless  a  HCB  (hidden  control  block,  the  metadata  files  for
           posixovl) is found that can override these

       ·   all lower-level files will be operated on/created with the user who
           inititated the mount

       If no HCB exists for a file or directory, the default  permissions  are
       rw-r--r--  or rwxr-xr-x, respectively. The owner and group of the inode
       will be the owner/group of the real file.

       Each non-regular, non-directory virtual file will have a zero-size real
       file.   (Simplifies  handling, and makes it apprarent the object exists
       when using other operating systems.)

       `df` will show:
       $ df -Tah
       Filesystem    Type    Size  Used Avail Use% Mounted on
       /dev/hda5     vfat    5.9G  2.1G  3.9G  35% /windows/D
       posix-overlay(/windows/D)
            fuse.posixovl    5.9G  2.1G  3.9G  35% /windows/D

       In general, posixovl does not handle case-insensitivity of the underly‐
       ing  filesystem  (in  case  of vfat, for example). If you create a file
       "X0" on vfat, it is usually lowercased to "x0", which  may  break  some
       software,  namely X.org.  In order to make vfat behave more POSIX-like,
       the following mount options are recommended:

       $ mount -t vfat /dev/hda1 /windows/D -o check=s,shortname=mixed

Authors
-------

       posixovl and this manpage were written by Jan Engelhardt.

       Development of posixovl was sponsored by Slax (http://www.slax.org/).

       This github repository is a fork of
       https://sourceforge.net/p/posixovl/posixovl
