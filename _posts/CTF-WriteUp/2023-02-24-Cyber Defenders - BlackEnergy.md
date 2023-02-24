---
title: "Cyber Defenders: BlackEnergy"
classes: wide
header:
  teaser: /assets/images/CTF-WriteUp/BlackEnergy/Capture.PNG
ribbon: gold
description: "Scenario:
A multinational corporation has been hit by a cyber attack that has led to the theft of sensitive data. The attack was carried out using a variant of the BlackEnergy v2 malware that has never been seen before. The company's security team has acquired a memory dump of the infected machine, and they want you to analyze the dump to understand the attack scope and impact."
categories:
  - CTF-WriteUp
toc: true
---

<span style="color: #909090">Category: Volatility, Windows, Memory</span>

> Challenge : [Challenge Link](https://cyberdefenders.org/blueteam-ctf-challenges/99)

**Scenario:**
A multinational corporation has been hit by a cyber attack that has led to the theft of sensitive data. The attack was carried out using a variant of the BlackEnergy v2 malware that has never been seen before. The company's security team has acquired a memory dump of the infected machine, and they want you to analyze the dump to understand the attack scope and impact.

# Tools
   * <a href="https://github.com/volatilityfoundation/volatility" style="color:#808080;">volatility2</a>

# #1	Which volatility profile would be best for this machine?

So First we need to determine which profile this image is. we can start with `imageinfo` to see what we will get.

```
Suggested Profile(s) : `WinXPSP2x86`, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace 
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cde0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2023-02-13 18:29:11 UTC+0000
     Image local date and time : 2023-02-13 10:29:11 -0800
```

we can see that the Suggested Profile `WinXPSP2x86`.

Flag : <span style="color: #909090">WinXPSP2x86</span>

# #2 How many processes were running when the image was acquired?

We can list processes and then see what an active process. so after getting the result from pslist.
```
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x89c037f8 System                    4      0     55      245 ------      0                                                              
0x89965020 smss.exe                368      4      3       19 ------      0 2023-02-14 04:54:15 UTC+0000                                 
0x89a98da0 csrss.exe               592    368     11      321      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89a88da0 winlogon.exe            616    368     18      508      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89938998 services.exe            660    616     15      240      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89aa0020 lsass.exe               672    616     21      335      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89aaa3d8 VBoxService.exe         832    660      9      115      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89aab590 svchost.exe             880    660     21      295      0      0 2023-02-13 17:54:16 UTC+0000                                 
0x89a9f6f8 svchost.exe             968    660     10      244      0      0 2023-02-13 17:54:17 UTC+0000                                 
0x89730da0 svchost.exe            1060    660     51     1072      0      0 2023-02-13 17:54:17 UTC+0000                                 
0x897289a8 svchost.exe            1108    660      5       78      0      0 2023-02-13 17:54:17 UTC+0000                                 
0x899adda0 svchost.exe            1156    660     13      192      0      0 2023-02-13 17:54:17 UTC+0000                                 
0x89733938 explorer.exe           1484   1440     14      489      0      0 2023-02-13 17:54:18 UTC+0000                                 
0x897075d0 spoolsv.exe            1608    660     10      106      0      0 2023-02-13 17:54:18 UTC+0000                                 
0x8969188 wscntfy.exe             480   1060      1       28      0      0 2023-02-13 17:54:30 UTC+0000                                 
0x8969d2a0 alg.exe                 540    660      5      102      0      0 2023-02-13 17:54:30 UTC+0000                                 
0x89982da0 VBoxTray.exe            376   1484     13      125      0      0 2023-02-13 17:54:30 UTC+0000                                 
0x8994a020 msmsgs.exe              636   1484      2      157      0      0 2023-02-13 17:54:30 UTC+0000                                 
0x89a0b2f0 taskmgr.exe            1880   1484      0 --------      0      0 2023-02-13 18:25:15 UTC+0000   2023-02-13 18:26:21 UTC+0000  
0x899dd740 rootkit.exe             964   1484      0 --------      0      0 2023-02-13 18:25:26 UTC+0000   2023-02-13 18:25:26 UTC+0000  
0x89a18da0 cmd.exe                1960    964      0 --------      0      0 2023-02-13 18:25:26 UTC+0000   2023-02-13 18:25:26 UTC+0000  
0x896c5020 notepad.exe             528   1484      0 --------      0      0 2023-02-13 18:26:55 UTC+0000   2023-02-13 18:27:46 UTC+0000  
0x89a0d180 notepad.exe            112   1484      0 --------      0      0 2023-02-13 18:28:25 UTC+0000   2023-02-13 18:28:40 UTC+0000  
0x899e6da0 notepad.exe            1444   1484      0 --------      0      0 2023-02-13 18:28:42 UTC+0000   2023-02-13 18:28:47 UTC+0000  
0x89a0fda0 DumpIt.exe              276   1484      1       25      0      0 2023-02-13 18:29:08 UTC+0000       
```

we will notice that they are 25 processes but we need only the active process. so we have 19 processes only since that they are 6 processes have been terminated (taskmgr.exe, rootkit.exe, cmd.exe, notepad.exe, notepad.exe, notepad.exe).

Flag : <span style="color: #909090">19</span>

# #3 What is the process ID of cmd.exe?

The Process ID (PID) is a unique identifier assigned to a process running on a computer system. It is used to differentiate between multiple running processes and to perform various process-related operations. We can get it using `pslist` plugin from volatility.

```
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x89c037f8 System                    4      0     55      245 ------      0                                                              
0x89965020 smss.exe                368      4      3       19 ------      0 2023-02-14 04:54:15 UTC+0000                                 
0x89a98da0 csrss.exe               592    368     11      321      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89a88da0 winlogon.exe            616    368     18      508      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89938998 services.exe            660    616     15      240      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89aa0020 lsass.exe               672    616     21      335      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89aaa3d8 VBoxService.exe         832    660      9      115      0      0 2023-02-14 04:54:15 UTC+0000                                 
0x89aab590 svchost.exe             880    660     21      295      0      0 2023-02-13 17:54:16 UTC+0000                                 
0x89a9f6f8 svchost.exe             968    660     10      244      0      0 2023-02-13 17:54:17 UTC+0000                                 
0x89730da0 svchost.exe            1060    660     51     1072      0      0 2023-02-13 17:54:17 UTC+0000                                 
0x897289a8 svchost.exe            1108    660      5       78      0      0 2023-02-13 17:54:17 UTC+0000                                 
0x899adda0 svchost.exe            1156    660     13      192      0      0 2023-02-13 17:54:17 UTC+0000                                 
0x89733938 explorer.exe           1484   1440     14      489      0      0 2023-02-13 17:54:18 UTC+0000                                 
0x897075d0 spoolsv.exe            1608    660     10      106      0      0 2023-02-13 17:54:18 UTC+0000                                 
0x8969188 wscntfy.exe             480   1060      1       28      0      0 2023-02-13 17:54:30 UTC+0000                                 
0x8969d2a0 alg.exe                 540    660      5      102      0      0 2023-02-13 17:54:30 UTC+0000                                 
0x89982da0 VBoxTray.exe            376   1484     13      125      0      0 2023-02-13 17:54:30 UTC+0000                                 
0x8994a020 msmsgs.exe              636   1484      2      157      0      0 2023-02-13 17:54:30 UTC+0000                                 
0x89a0b2f0 taskmgr.exe            1880   1484      0 --------      0      0 2023-02-13 18:25:15 UTC+0000   2023-02-13 18:26:21 UTC+0000  
0x899dd740 rootkit.exe             964   1484      0 --------      0      0 2023-02-13 18:25:26 UTC+0000   2023-02-13 18:25:26 UTC+0000  
0x89a18da0 cmd.exe                `1960`    964      0 --------      0      0 2023-02-13 18:25:26 UTC+0000   2023-02-13 18:25:26 UTC+0000  
0x896c5020 notepad.exe             528   1484      0 --------      0      0 2023-02-13 18:26:55 UTC+0000   2023-02-13 18:27:46 UTC+0000  
0x89a0d180 notepad.exe            112   1484      0 --------      0      0 2023-02-13 18:28:25 UTC+0000   2023-02-13 18:28:40 UTC+0000  
0x899e6da0 notepad.exe            1444   1484      0 --------      0      0 2023-02-13 18:28:42 UTC+0000   2023-02-13 18:28:47 UTC+0000  
0x89a0fda0 DumpIt.exe              276   1484      1       25      0      0 2023-02-13 18:29:08 UTC+0000                
```

Flag : <span style="color: #909090">1960</span>

# #4 What is the name of the most suspicious process?

We can also get this suspicious process from the result of pslist. We will see that there is a process called `rootkit.exe` which is not normal as it's obvious from its name. we can also double-check from `pstree` plugin.

```
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x89c037f8:System                                      4      0     55    245 1970-01-01 00:00:00 UTC+0000
. 0x89965020:smss.exe                                 368      4      3     19 2023-02-14 04:54:15 UTC+0000
.. 0x89a98da0:csrss.exe                               592    368     11    321 2023-02-14 04:54:15 UTC+0000
.. 0x89a88da0:winlogon.exe                            616    368     18    508 2023-02-14 04:54:15 UTC+0000
... 0x89938998:services.exe                           660    616     15    240 2023-02-14 04:54:15 UTC+0000
.... 0x899adda0:svchost.exe                          1156    660     13    192 2023-02-13 17:54:17 UTC+0000
.... 0x8969d2a0:alg.exe                               540    660      5    102 2023-02-13 17:54:30 UTC+0000
.... 0x89aab590:svchost.exe                           880    660     21    295 2023-02-13 17:54:16 UTC+0000
.... 0x89730da0:svchost.exe                          1060    660     51   1072 2023-02-13 17:54:17 UTC+0000
..... 0x8969188:wscntfy.exe                          480   1060      1     28 2023-02-13 17:54:30 UTC+0000
.... 0x89a9f6f8:svchost.exe                           968    660     10    244 2023-02-13 17:54:17 UTC+0000
.... 0x89aaa3d8:VBoxService.exe                       832    660      9    115 2023-02-14 04:54:15 UTC+0000
.... 0x897075d0:spoolsv.exe                          1608    660     10    106 2023-02-13 17:54:18 UTC+0000
.... 0x897289a8:svchost.exe                          1108    660      5     78 2023-02-13 17:54:17 UTC+0000
... 0x89aa0020:lsass.exe                              672    616     21    335 2023-02-14 04:54:15 UTC+0000
 0x89733938:explorer.exe                             1484   1440     14    489 2023-02-13 17:54:18 UTC+0000
. 0x896c5020:notepad.exe                              528   1484      0 ------ 2023-02-13 18:26:55 UTC+0000
. 0x89a0d180:notepad.exe                             112   1484      0 ------ 2023-02-13 18:28:25 UTC+0000
. 0x899dd740:rootkit.exe                              964   1484      0 ------ 2023-02-13 18:25:26 UTC+0000
.. 0x89a18da0:cmd.exe                                1960    964      0 ------ 2023-02-13 18:25:26 UTC+0000
. 0x89a0b2f0:taskmgr.exe                             1880   1484      0 ------ 2023-02-13 18:25:15 UTC+0000
. 0x899e6da0:notepad.exe                             1444   1484      0 ------ 2023-02-13 18:28:42 UTC+0000
. 0x89982da0:VBoxTray.exe                             376   1484     13    125 2023-02-13 17:54:30 UTC+0000
. 0x89a0fda0:DumpIt.exe                               276   1484      1     25 2023-02-13 18:29:08 UTC+0000
. 0x8994a020:msmsgs.exe                               636   1484      2    157 2023-02-13 17:54:30 UTC+0000
```

we will notice that this process is a child from `explorer.exe` and has `cmd.exe` child also this is not normal behavior.

Flag : <span style="color: #909090">rootkit.exe</span>

# #5 Which process shows the highest likelihood of code injection?

We can use `malfind` plugin to check for that. malfind plugin searches the memory dump for suspicious code injection artifacts, including injected DLLs, and other memory code injection techniques.

```
Process: `svchost.exe` Pid: 880 Address: `0x980000`
Vad Tag: VadS Protection: `PAGE_EXECUTE_READWRITE`
Flags: CommitCharge: 9, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x0000000000980000  `4d 5a` 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   `MZ`..............
0x0000000000980010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x0000000000980020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000000980030  00 00 00 00 00 00 00 00 00 00 00 00 f8 00 00 00   ................

0x0000000000980000 4d               DEC EBP
0x0000000000980001 5a               POP EDX
0x0000000000980002 90               NOP
0x0000000000980003 0003             ADD [EBX], AL
0x0000000000980005 0000             ADD [EAX], AL
0x0000000000980007 000400           ADD [EAX+EAX], AL
0x000000000098000a 0000             ADD [EAX], AL
0x000000000098000c ff               DB 0xff
0x000000000098000d ff00             INC DWORD [EAX]
0x000000000098000f 00b800000000     ADD [EAX+0x0], BH
0x0000000000980015 0000             ADD [EAX], AL
0x0000000000980017 004000           ADD [EAX+0x0], AL
0x000000000098001a 0000             ADD [EAX], AL
0x000000000098001c 0000             ADD [EAX], AL
0x000000000098001e 0000             ADD [EAX], AL
0x0000000000980020 0000             ADD [EAX], AL
0x0000000000980022 0000             ADD [EAX], AL
0x0000000000980024 0000             ADD [EAX], AL
0x0000000000980026 0000             ADD [EAX], AL
0x0000000000980028 0000             ADD [EAX], AL
0x000000000098002a 0000             ADD [EAX], AL
0x000000000098002c 0000             ADD [EAX], AL
0x000000000098002e 0000             ADD [EAX], AL
0x0000000000980030 0000             ADD [EAX], AL
0x0000000000980032 0000             ADD [EAX], AL
0x0000000000980034 0000             ADD [EAX], AL
0x0000000000980036 0000             ADD [EAX], AL
0x0000000000980038 0000             ADD [EAX], AL
0x000000000098003a 0000             ADD [EAX], AL
0x000000000098003c f8               CLC
0x000000000098003d 0000             ADD [EAX], AL
0x000000000098003f 00               DB 0x0
```

So here we will see from the output of `malfind` that there is a suspicious process which is `svchost.exe` but how?. we can see VadS Protection: `PAGE_EXECUTE_READWRITE` which means the memory region is writable and executable but that means that the executable is not normally loaded and it's injected! also as we see Magic number: A 2-byte value (0x4D5A) that identifies the file as an executable file in the MZ format. can we prove that ? of course. let's dump it using `malfind -p 880 -D ./` and go to virustotal to see what we will get.

[![1](/assets/images/CTF-WriteUp/BlackEnergy/1.PNG)](/assets/images/CTF-WriteUp/BlackEnergy/1.PNG)

so this is the process that shows the highest likelihood of code injection. We can also see that we now deal with the famous Rootkit BlackEnergy as it's obvious from the name of the challenge. Black Energy is a sophisticated rootkit that has been used by cybercriminals to target various organizations and critical infrastructure systems, particularly in Ukraine. It was first discovered in 2007 and has since undergone several updates and modifications to make it more difficult to detect and remove.

Flag : <span style="color: #909090">svchost.exe</span>

# #6 There is an odd file referenced in the recent process. Provide the full path of that file.

We can use the PID of the process `880` and search for handles of this process. Handles can be used to determine the relationships between processes, identify open files and network connections, and locate hidden or malicious processes. we can use `handles` plugin and specify the PID of the process and filter only files since we know from the question that we need to find file `handles -p 880 -t File`.

```
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0x89a28890    880        0xc   0x100020 File             \Device\HarddiskVolume1\WINDOWS\system32
0x89a1a6f8    880       0x50   0x100001 File             \Device\KsecDD
0x89937358    880       0x68   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x899d0250    880       0xbc   0x12019f File             \Device\NamedPipe\net\NtControlPipe2
0x89a17a50    880      0x100   0x100000 File             \Device\Dfs
0x89732cb8    880      0x158   0x12019f File             \Device\NamedPipe\lsarpc
0x8969fee0    880      0x274   0x12019f File             \Device\Termdd
0x89ab3478    880      0x294   0x12019f File             \Device\Termdd
0x89ab3978    880      0x29c   0x12019f File             \Device\Termdd
0x896bcd18    880      0x2b8   0x12019f File             \Device\NamedPipe\Ctx_WinStation_API_service
0x8997a248    880      0x2bc   0x12019f File             \Device\NamedPipe\Ctx_WinStation_API_service
0x899a24b0    880      0x304   0x12019f File             \Device\Termdd
0x89a00f90    880      0x33c   0x12019f File             \Device\{9DD6AFA1-8646-4720-836B-EDCB1085864A}
`0x89af0cf0    880      0x340   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\drivers\str.sys`
0x89993f90    880      0x3d8   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89958b78    880      0x3e4   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Local Settings\Temporary Internet Files\Content.IE5\index.dat
0x899fe2e0    880      0x3f8   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Cookies\index.dat
0x89a492e8    880      0x400   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Local Settings\History\History.IE5\index.dat
0x896811d8    880      0x424   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89bbc028    880      0x488   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89999980    880      0x4a8   0x1200a0 File             \Device\NetBT_Tcpip_{B35F0A5F-EBC3-4B5D-800D-7C1B64B30F14}
```

we found this `\Device\HarddiskVolume1\WINDOWS\system32\drivers\str.sys` that is strange. we can also find it in the strings output of the dumped process.

[![2](/assets/images/CTF-WriteUp/BlackEnergy/2.PNG)](/assets/images/CTF-WriteUp/BlackEnergy/2.PNG)

Flag : <span style="color: #909090">C:\WINDOWS\system32\drivers\str.sys</span>

# #7 What is the name of the injected dll file loaded from the recent process?

Reflective DLL Injection: Reflective DLL injection is a technique that allows an attacker to inject a DLL's into a victim process from memory rather than disk. We can use `ldrmodules` plugin and specify the PID of that process `880` to get that. ldrmodules plugin lists all the DLLs that have been loaded into the memory space of the specified process, along with their base addresses, size, and path on the file system. This information can be useful in identifying any malicious DLLs that may have been injected into the process's memory space or to determine the modules that are causing the process to behave unexpectedly.

```
Pid      Process              Base       InLoad InInit InMem MappedPath
-------- -------------------- ---------- ------ ------ ----- ----------
     880 svchost.exe          0x6f880000 True   True   True  \WINDOWS\AppPatch\AcGenral.dll
     880 svchost.exe          0x01000000 True   False  True  \WINDOWS\system32\svchost.exe
     880 svchost.exe          0x77f60000 True   True   True  \WINDOWS\system32\shlwapi.dll
     880 svchost.exe          0x74f70000 True   True   True  \WINDOWS\system32\icaapi.dll
     880 svchost.exe          0x76f60000 True   True   True  \WINDOWS\system32\wldap32.dll
     880 svchost.exe          0x77c00000 True   True   True  \WINDOWS\system32\version.dll
     880 svchost.exe          0x5ad70000 True   True   True  \WINDOWS\system32\uxtheme.dll
     880 svchost.exe          0x76e80000 True   True   True  \WINDOWS\system32\rtutils.dll
     880 svchost.exe          0x771b0000 True   True   True  \WINDOWS\system32\wininet.dll
     880 svchost.exe          0x76c90000 True   True   True  \WINDOWS\system32\imagehlp.dll
     880 svchost.exe          0x76bc0000 True   True   True  \WINDOWS\system32\regapi.dll
     880 svchost.exe          0x77dd0000 True   True   True  \WINDOWS\system32\advapi32.dll
     880 svchost.exe          0x76f20000 True   True   True  \WINDOWS\system32\dnsapi.dll
     880 svchost.exe          0x77be0000 True   True   True  \WINDOWS\system32\msacm32.dll
     880 svchost.exe          0x7e1e0000 True   True   True  \WINDOWS\system32\urlmon.dll
     880 svchost.exe          0x68000000 True   True   True  \WINDOWS\system32\rsaenh.dll
     880 svchost.exe          0x722b0000 True   True   True  \WINDOWS\system32\sensapi.dll
     880 svchost.exe          0x76e10000 True   True   True  \WINDOWS\system32\adsldpc.dll
     880 svchost.exe          0x76b40000 True   True   True  \WINDOWS\system32\winmm.dll
     880 svchost.exe          0x773d0000 True   True   True  \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll
     880 svchost.exe          0x71a50000 True   True   True  \WINDOWS\system32\mswsock.dll
     880 svchost.exe          0x5b860000 True   True   True  \WINDOWS\system32\netapi32.dll
     880 svchost.exe          0x00670000 True   True   True  \WINDOWS\system32\xpsp2res.dll
     880 svchost.exe          0x76e90000 True   True   True  \WINDOWS\system32\rasman.dll
     880 svchost.exe          0x77a80000 True   True   True  \WINDOWS\system32\crypt32.dll
     880 svchost.exe          0x71ab0000 True   True   True  \WINDOWS\system32\ws2_32.dll
     880 svchost.exe          0x77cc0000 True   True   True  \WINDOWS\system32\activeds.dll
     880 svchost.exe          0x71ad0000 True   True   True  \WINDOWS\system32\wsock32.dll
     880 svchost.exe          0x774e0000 True   True   True  \WINDOWS\system32\ole32.dll
     880 svchost.exe          0x77920000 True   True   True  \WINDOWS\system32\setupapi.dll
     880 svchost.exe          0x7e410000 True   True   True  \WINDOWS\system32\user32.dll
     880 svchost.exe          0x7c900000 True   True   True  \WINDOWS\system32\ntdll.dll
     880 svchost.exe          0x77f10000 True   True   True  \WINDOWS\system32\gdi32.dll
     880 svchost.exe          0x77120000 True   True   True  \WINDOWS\system32\oleaut32.dll
     880 svchost.exe          0x5cb70000 True   True   True  \WINDOWS\system32\shimeng.dll
     880 svchost.exe          0x74980000 True   True   True  \WINDOWS\system32\msxml3.dll
     `880 svchost.exe          0x009a0000 False  False  False \WINDOWS\system32\msxml3r.dll`
     880 svchost.exe          0x77e70000 True   True   True  \WINDOWS\system32\rpcrt4.dll
     880 svchost.exe          0x769c0000 True   True   True  \WINDOWS\system32\userenv.dll
     880 svchost.exe          0x7c800000 True   True   True  \WINDOWS\system32\kernel32.dll
     880 svchost.exe          0x76fd0000 True   True   True  \WINDOWS\system32\clbcatq.dll
     880 svchost.exe          0x76b20000 True   True   True  \WINDOWS\system32\atl.dll
     880 svchost.exe          0x71bf0000 True   True   True  \WINDOWS\system32\samlib.dll
     880 svchost.exe          0x77690000 True   True   True  \WINDOWS\system32\ntmarta.dll
     880 svchost.exe          0x77c10000 True   True   True  \WINDOWS\system32\msvcrt.dll
     880 svchost.exe          0x760f0000 True   True   True  \WINDOWS\system32\termsrv.dll
     880 svchost.exe          0x76fc0000 True   True   True  \WINDOWS\system32\rasadhlp.dll
     880 svchost.exe          0x76c30000 True   True   True  \WINDOWS\system32\wintrust.dll
     880 svchost.exe          0x7c9c0000 True   True   True  \WINDOWS\system32\shell32.dll
     880 svchost.exe          0x77050000 True   True   True  \WINDOWS\system32\comres.dll
     880 svchost.exe          0x76eb0000 True   True   True  \WINDOWS\system32\tapi32.dll
     880 svchost.exe          0x76a80000 True   True   True  \WINDOWS\system32\rpcss.dll
     880 svchost.exe          0x5d090000 True   True   True  \WINDOWS\system32\comctl32.dll
     880 svchost.exe          0x71aa0000 True   True   True  \WINDOWS\system32\ws2help.dll
     880 svchost.exe          0x776c0000 True   True   True  \WINDOWS\system32\authz.dll
     880 svchost.exe          0x76ee0000 True   True   True  \WINDOWS\system32\rasapi32.dll
     880 svchost.exe          0x77b20000 True   True   True  \WINDOWS\system32\msasn1.dll
     880 svchost.exe          0x75110000 True   True   True  \WINDOWS\system32\mstlsapi.dll
     880 svchost.exe          0x77fe0000 True   True   True  \WINDOWS\system32\secur32.dll
```

we can notice here that there is `\WINDOWS\system32\msxml3r.dll` that seems to be unlinked in all three ldr module lists. This is the sign of dll hiding where the dll is unlinked from the doubly linked lists in PEB. which is suspicious.

Flag : <span style="color: #909090">msxml3r.dll</span>

# #8 What is the base address of the injected dll?

I used `dlllist` plugin but I didn't find it so it could mean that the DLL has been hidden or removed from the memory space of the process. We can get back to `malfind` to get it and also specify the process PID `880`.

```
Process: svchost.exe Pid: 880 Address: `0x980000`
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 9, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x0000000000980000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x0000000000980010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x0000000000980020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000000980030  00 00 00 00 00 00 00 00 00 00 00 00 f8 00 00 00   ................

0x0000000000980000 4d               DEC EBP
0x0000000000980001 5a               POP EDX
0x0000000000980002 90               NOP
0x0000000000980003 0003             ADD [EBX], AL
0x0000000000980005 0000             ADD [EAX], AL
0x0000000000980007 000400           ADD [EAX+EAX], AL
0x000000000098000a 0000             ADD [EAX], AL
0x000000000098000c ff               DB 0xff
0x000000000098000d ff00             INC DWORD [EAX]
0x000000000098000f 00b800000000     ADD [EAX+0x0], BH
0x0000000000980015 0000             ADD [EAX], AL
0x0000000000980017 004000           ADD [EAX+0x0], AL
0x000000000098001a 0000             ADD [EAX], AL
0x000000000098001c 0000             ADD [EAX], AL
0x000000000098001e 0000             ADD [EAX], AL
0x0000000000980020 0000             ADD [EAX], AL
0x0000000000980022 0000             ADD [EAX], AL
0x0000000000980024 0000             ADD [EAX], AL
0x0000000000980026 0000             ADD [EAX], AL
0x0000000000980028 0000             ADD [EAX], AL
0x000000000098002a 0000             ADD [EAX], AL
0x000000000098002c 0000             ADD [EAX], AL
0x000000000098002e 0000             ADD [EAX], AL
0x0000000000980030 0000             ADD [EAX], AL
0x0000000000980032 0000             ADD [EAX], AL
0x0000000000980034 0000             ADD [EAX], AL
0x0000000000980036 0000             ADD [EAX], AL
0x0000000000980038 0000             ADD [EAX], AL
0x000000000098003a 0000             ADD [EAX], AL
0x000000000098003c f8               CLC
0x000000000098003d 0000             ADD [EAX], AL
0x000000000098003f 00               DB 0x0
```

We can get the Base Address `0x980000`.

Flag : <span style="color: #909090">0x980000</span>

And finally, it’s the end, and I hope you enjoyed this :).

[![giphy](/assets/images/CTF-WriteUp/BlackEnergy/giphy.gif)](/assets/images/CTF-WriteUp/BlackEnergy/giphy.gif)

# Refrences 
[Reflective DLL Injection](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection)