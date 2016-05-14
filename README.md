Volatility ProfileScan
======================

First approach at determining any information about the OS lying into a memory
dump. Based on simple occurences counting, but quite accurate.

Useful for choosing a profile for analysis in Volatility after.

The same things can be done with grep, which may be way faster (but less
accurate). But I wanted something architecture independant and which fits into
Volatility.

Problems right now:
* It the user runs a VM, detection might return the VM's OS.
* Quite slow
* Few informations (mac_get_profile only works with Mavericks?)

## Demo on the batch of samples from AMF:

This is a small sample of what the plugin can do when asked to recover the dump's
OS with a minimum of 20 caracteristic executable. This means, an OS 'wins' only
when 90% minimum of the executables found are his (exe->windows, elf->linux...),
with at least 20 executables found.

### dumps/linux1.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 2.6.18-8.1.15.el5
    Compiled by   : (mockbuild@builder6.centos.org)
    Compiler      : (gcc version 4.1.1 20070105 (Red Hat 4.1.1-52))
Profile: Red Hat (2.6.18-8.1.15.el5)
real	0m1.838s
user	0m1.787s
sys	0m0.053s
```



### dumps/linux2.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 2.6.26-2-686
    Compiled by   : (dannf@debian.org)
    Compiler      : (gcc version 4.1.3 20080704 (prerelease) (Debian 4.1.2-25))
Profile: Debian (2.6.26-2-686)
real	0m4.693s
user	0m4.617s
sys	0m0.063s
```



### dumps/linuxdebian2.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 2.6.26-2-686
    Compiled by   : (dannf@debian.org)
    Compiler      : (gcc version 4.1.3 20080704 (prerelease) (Debian 4.1.2-25))
Profile: Debian (2.6.26-2-686)
real	0m4.587s
user	0m4.540s
sys	0m0.043s
```



### dumps/linuxdebian.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 2.6.32-5-amd64
    Compiled by   : (jmm@debian.org)
    Compiler      : (gcc version 4.3.5 (Debian 4.3.5-4) )
Profile: Debian (2.6.32-5-amd64)
real	0m39.429s
user	0m39.343s
sys	0m0.077s
```



### dumps/linux-sample-1.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 3.2.0-4-amd64
    Compiled by   : (debian-kernel@lists.debian.org)
    Compiler      : (gcc version 4.6.3 (Debian 4.6.3-14) )
Profile: Debian (3.2.0-4-amd64)
real	0m36.724s
user	0m36.650s
sys	0m0.070s
```



### dumps/linux-sample-2.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 3.2.0-4-amd64
    Compiled by   : (debian-kernel@lists.debian.org)
    Compiler      : (gcc version 4.6.3 (Debian 4.6.3-14) )
Profile: Debian (3.2.0-4-amd64)
real	0m23.700s
user	0m23.607s
sys	0m0.090s
```



### dumps/linux-sample-3.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 3.2.0-4-amd64
    Compiled by   : (debian-kernel@lists.debian.org)
    Compiler      : (gcc version 4.6.3 (Debian 4.6.3-14) )
Profile: Debian (3.2.0-4-amd64)
real	0m18.267s
user	0m18.177s
sys	0m0.070s
```



### dumps/linux-sample-4.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 3.2.0-4-amd64
    Compiled by   : (debian-kernel@lists.debian.org)
    Compiler      : (gcc version 4.6.3 (Debian 4.6.3-14) )
Profile: Debian (3.2.0-4-amd64)
real	0m17.204s
user	0m17.123s
sys	0m0.073s
```



### dumps/linux-sample-5.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 3.2.0-4-amd64
    Compiled by   : (debian-kernel@lists.debian.org)
    Compiler      : (gcc version 4.6.3 (Debian 4.6.3-14) )
Profile: Debian (3.2.0-4-amd64)
real	0m18.096s
user	0m18.030s
sys	0m0.063s
```



### dumps/linux-sample-6.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 3.2.0-4-amd64
    Compiled by   : (debian-kernel@lists.debian.org)
    Compiler      : (gcc version 4.6.3 (Debian 4.6.3-14) )
Profile: Debian (3.2.0-4-amd64)
real	0m45.480s
user	0m45.400s
sys	0m0.077s
```



### dumps/linuxstrange2.bin
 ```console

Volatility Foundation Volatility Framework 2.5
OS not found.
real	0m2.298s
user	0m2.240s
sys	0m0.057s
```



### dumps/linuxstrange.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 2.6.35.10-gc0a661b
    Compiled by   : (joe@zuul)
    Compiler      : (gcc version 4.4.3 (GCC) )
Profile: Distribution Not found (2.6.35.10-gc0a661b)
real	2m25.543s
user	2m25.410s
sys	0m0.097s
```



### dumps/linuxubuntu.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: LINUX - Launching LinuxGetProfile
Informations found:
    Kernel version: 3.5.0-23-generic
    Compiled by   : (buildd@komainu)
    Compiler      : (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) )
Profile: Ubuntu (3.5.0-23-generic)
real	0m23.214s
user	0m23.160s
sys	0m0.050s
```



### dumps/mac-sample-1.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: OSX - Launching mac_get_profile
Profile                                            Shift Address
-------------------------------------------------- -------------
MacMavericks_10_9_3_AMDx64                         0x0000d400000

real	0m16.896s
user	0m16.770s
sys	0m0.103s
```



### dumps/mac-sample-2.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: OSX - Launching mac_get_profile
Profile                                            Shift Address
-------------------------------------------------- -------------
MacMavericks_10_9_3_AMDx64                         0x0002d200000

real	0m14.751s
user	0m14.590s
sys	0m0.157s
```



### dumps/mac-sample-3.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: OSX - Launching mac_get_profile
Profile                                            Shift Address
-------------------------------------------------- -------------
MacMavericks_10_9_3_AMDx64                         0x0000fa00000

real	0m31.445s
user	0m31.340s
sys	0m0.100s
```



### dumps/mac-sample-4.bin
 ```console

Volatility Foundation Volatility Framework 2.5
Found OS: OSX - Launching mac_get_profile
Profile                                            Shift Address
-------------------------------------------------- -------------
MacMavericks_10_9_3_AMDx64                         0x00027600000

real	0m8.057s
user	0m7.910s
sys	0m0.143s
```



### dumps/sample001.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (dumps/sample001.bin)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cde0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2012-11-27 01:57:28 UTC+0000
     Image local date and time : 2012-11-26 19:57:28 -0600

real	0m41.623s
user	0m41.370s
sys	0m0.250s
```



### dumps/sample002.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : Win7SP0x86, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (dumps/sample002.bin)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x8292dc28L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x8292ec00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2013-10-15 18:49:01 UTC+0000
     Image local date and time : 2013-10-15 14:49:01 -0400

real	0m39.201s
user	0m38.057s
sys	0m1.140s
```



### dumps/sample003.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (dumps/sample003.bin)
                      PAE type : PAE
                           DTB : 0x319000L
                          KDBG : 0x80545b60L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2008-11-26 07:46:02 UTC+0000
     Image local date and time : 2008-11-26 02:46:02 -0500

real	0m29.398s
user	0m29.143s
sys	0m0.253s
```



### dumps/sample004.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (dumps/sample004.bin)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cde0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2012-04-28 02:23:21 UTC+0000
     Image local date and time : 2012-04-27 22:23:21 -0400

real	0m46.398s
user	0m46.110s
sys	0m0.283s
```



### dumps/sample005.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : Win2003SP0x86, Win2003SP1x86, Win2003SP2x86 (Instantiated with LinuxDebian40r9x86)
                     AS Layer1 : FileAddressSpace (dumps/sample005.bin)
                      PAE type : No PAE
                           DTB : -0x1L
Traceback (most recent call last):
  File "/usr/bin/volatility", line 192, in <module>
    main()
  File "/usr/bin/volatility", line 183, in main
    command.execute()
  File "/usr/lib/python2.7/site-packages/volatility/commands.py", line 145, in execute
    func(outfd, data)
  File "/usr/lib/python2.7/site-packages/volatility/plugins/profilescan.py", line 178, in render_text
    image.render_text(outfd, image.calculate())
  File "/usr/lib/python2.7/site-packages/volatility/plugins/imageinfo.py", line 45, in render_text
    for k, t, v in data:
  File "/usr/lib/python2.7/site-packages/volatility/plugins/imageinfo.py", line 103, in calculate
    kdbg = volmagic.KDBG.v()
  File "/usr/lib/python2.7/site-packages/volatility/obj.py", line 748, in __getattr__
    return self.m(attr)
  File "/usr/lib/python2.7/site-packages/volatility/obj.py", line 730, in m
    raise AttributeError("Struct {0} has no member {1}".format(self.obj_name, attr))
AttributeError: Struct VOLATILITY_MAGIC has no member KDBG

real	1m3.432s
user	1m0.697s
sys	0m2.730s
```



### dumps/sample006.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (dumps/sample006.bin)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cde0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2010-09-09 19:56:54 UTC+0000
     Image local date and time : 2010-09-09 15:56:54 -0400

real	0m17.102s
user	0m16.773s
sys	0m0.300s
```



### dumps/sample007.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (dumps/sample007.bin)
                      PAE type : PAE
                           DTB : 0x319000L
                          KDBG : 0x80545ae0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2011-06-03 04:31:36 UTC+0000
     Image local date and time : 2011-06-03 00:31:36 -0400

real	0m40.003s
user	0m39.680s
sys	0m0.320s
```



### dumps/sample008.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (dumps/sample008.bin)
                      PAE type : PAE
                           DTB : 0x319000L
                          KDBG : 0x80544ce0L
          Number of Processors : 1
     Image Type (Service Pack) : 2
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2010-08-15 19:26:50 UTC+0000
     Image local date and time : 2010-08-15 15:26:50 -0400

real	0m15.566s
user	0m15.263s
sys	0m0.300s
```



### dumps/sample009.bin
 ```console

Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
Found OS: WINDOWS - Launching ImageInfo
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (dumps/sample009.bin)
                      PAE type : PAE
                           DTB : 0x339000L
                          KDBG : 0x80545ae0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2014-11-29 15:33:20 UTC+0000
     Image local date and time : 2014-11-30 02:33:20 +1100

real	1m6.902s
user	0m21.073s
sys	0m0.767s
```



