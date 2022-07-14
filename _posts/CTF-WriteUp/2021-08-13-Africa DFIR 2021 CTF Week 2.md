---
title: "Africa DFIR CTF Week 2"
classes: wide
header:
  teaser: /assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture.PNG
ribbon: Beige
description: "This is Week 2 from Africa DFIR CTF, which talks about Memory Dump Forensics."
categories:
  - CTF-WriteUp
toc: true
---

<span style="color: #909090">Category: Digital Forensics</span>

> Challenge : [Week 2](https://archive.org/download/Africa-DFIRCTF-2021-WK02)

This week is talk about ram forensics. Memory forensics (sometimes referred to as memory analysis) refers to the analysis of volatile data in a computer's memory dump. Information security professionals conduct memory forensics to investigate and identify attacks or malicious behaviors that do not leave easily detectable tracks on hard drive data.

we will use of course [volatility3](https://github.com/volatilityfoundation/volatility3). also this will help us to fix the messy output formatting of [volatility 3](https://twitter.com/vinopaljiri/status/1401724169847545857).

# Be Brave:

[![1](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture1.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture1.PNG)

here in the description he talk about process ID for application brave. In computing, the process identifier (a.k.a. process ID or PID) is a number used by most operating system kernels—such as those of Unix, macOS and Windows—to uniquely identify an active process. This number may be used as a parameter in various function calls, allowing processes to be manipulated, such as adjusting the process's priority or killing it altogether.

in volatility there is a plugin called windows.pslist.PsList which list all the process with the PID which we need for the flag.

[![2](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture2.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture2.PNG)

Flag : <span style="color: #909090">4856</span>

# Image Verification:

[![3](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture3.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture3.PNG)

that is quite easy. we can get the sha256 hash value from windows Powershell with this Powershell utility [Get-FileHash](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.1) :

then we will find the hash.

[![4](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture4.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture4.PNG)

Flag : <span style="color: #909090">9DB01B1E7B19A3B2113BFB65E860FFFD7A1630BDF2B18613D206EBF2AA0EA172</span>

# Let's Connect:

[![5](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture5.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture5.PNG)

here we talk about established network connections but wait what is the time of the acquisition it's the time of capturing, dumping, sampling involves copying the contents of volatile memory to non-volatile storage. so to find this we will use a plugin in volatility calls `windows.info.Info` which shows OS & kernel details of the memory sample.

[![6](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture6.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture6.PNG)

Time : <span style="color: #909090">2021-04-30 17:52:19</span>

now we know the acquisition time of memory. so let's find the established network connection but first what is an established network connection?
Any `ESTABLISHED` socket means that there is a connection currently made there. Cool.
how do know how many ESTABLISHED network connections ? there is a plugin in volatility that scan for network information in the memory calls `windows.netscan.NetScan`.

[![7](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture7.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture7.PNG)

and we will see that they are at the time of the acquisition.

Flag : <span style="color: #909090">10</span>

# RAM Acquisition Time:

[![8](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture8.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture8.PNG)

this we already solved in the previous challenge.

[![6](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture6.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture6.PNG)

Flag : <span style="color: #909090">2021-04-30 17:52:19</span>

# Chrome Connection:

[![9](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture9.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture9.PNG)

from `Let's Connect` we can see from the esatblished network connection that the chrome application made a connection with this IP address `185.70.41.130`.

[![10](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture10.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture10.PNG)

so I used this website to get the domain name of this. [ip address](https://www.whatismyip.com/185.70.41.130/)

[![11](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture11.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture11.PNG)

Flag : <span style="color: #909090">protonmail</span>

# Hash Hash Baby:

[![12](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture12.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture12.PNG)

in this challenge we need the hash `md5` of process memory that we know the process id of it PID `6988`, so we need to dump the process from the memory dump to calculate the hash for it. sure volatility has a plugin that can dump the process from the memory with its PID calls `windows.pslist.PsList` which has an argument that can dump the process.

[![13](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture13.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture13.PNG)

then we will get the hash `MD5` of the process dump.

[![14](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture14.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture14.PNG)

Flag : <span style="color: #909090">0b493d8e26f03ccd2060e0be85f430af</span>

# Offset Select:

[![15](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture15.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture15.PNG)

First, what is offset ?. The offset is the second part of a logical address that permits locating an Address inside a memory segment. An offset is not an address but the distance or id of this Address from the start of a memory segment starting at 0. An offset is also known as an effective address. to get the word starting at this offset `0x45BE876`. we can use any hex editor. in my case I will use bless hex editor then I will search with the offset to get the word as simple as that.

[![16](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture16.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture16.PNG)

Flag : <span style="color: #909090">hacker</span>

# Process Parents Please:

[![17](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture17.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture17.PNG)

first, what is the parent process and child process ?. Parent Process: All the processes are created when a process executes the fork() system call except the startup process. The process that executes the fork() system call is the parent process. A parent process creates a child process using a fork() system call. A parent process may have multiple child processes, but a child process only one parent process. to know the creation date and time of the parent process of `powershell.exe` we will use a plugin in volatility calls `windows.pstree.PsTree` to list in the shape of a tree the parent process branches from it the child process. I tried it but didn't work for me I think because it doesn't work at this time, no problem we will go back to `windows.pslist.PsList`. and search for `powershell.exe`.

[![18](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture18.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture18.PNG)

but how to know what is the parent process of powershell.exe ?. see that `PID` `5096` and that `PPID` `4352` from here we can find the parent process. but wait what is `PID` and `PPID` ? . `PID`: A process ID (PID) is a unique identifier assigned to a process while it runs. When the process ends, its PID is returned to the system. Each time you run a process, it has a different PID (it takes a long time for a PID to be reused by the system). You can use the PID to track the status of a process with the ps command or the jobs command, or to end a process with the kill command.` PPID`: A process that creates a new process is called a parent process; the new process is called a child process. The parent process ID (PPID) becomes associated with the new child process when it is created. The PPID is not used for job control.

so now if we search with the `PPID` of powershell.exe we will get the parent process which will be the `PID` of the parent process.

[![19](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture19.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture19.PNG)

Flag : <span style="color: #909090">2021-04-30 17:39:48</span>

# Finding Filenames:

[![20](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture20.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture20.PNG)

here we talk about the full path and name of the last file opened in notepad. to get that there is a plugin in `windows.cmdline.CmdLine`.
why this plugin? Commands entered into cmd.exe are processed by conhost.exe (csrss.exe prior to Windows 7). So even if an attacker managed to kill the cmd.exe prior to us obtaining a memory dump, there is still a good chance of recovering the history of the command line session from conhost.exe’s memory.

[![26](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture26.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture26.PNG)

Flag : <span style="color: #909090">C:\Users\JOHNDO~1\AppData\Local\Temp\7zO4FB31F24\accountNum</span>

# Hocus Focus:

[![21](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture21.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture21.PNG)

in this challenge, we talk about a time that the suspect used the Brave browser. when we talk about that I think about `User Assist`. What is User Assist? The UserAssist key, a part of the Microsoft Windows registry, records the information related to programs run by a user on a Windows system such as running count and last execution date and time. we are lucky that volatility has a plugin that gives us this information calls `windows.registry.userassist.UserAssist`.

[![25](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture25.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture25.PNG)

Flag : <span style="color: #909090">4:01:54</span>

# Meetings:

[![22](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture22.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture22.PNG)

here I don't know where to search or where could be the location of what I search about. I tried keyword search with autopsy but no luck with that until the hint we got that it's inside a pdf first come to my mind that we can search in metadata as if there is a location in pdf autopsy will detect that. bingo! there is a pdf called `almanac-start-a-garden.pdf`. when I searched in it I found this.

[![23](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture23.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture23.PNG)

if we take this coordinate to any online website to get location we will find the flag.

[![24](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture24.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture24.PNG)

Flag : <span style="color: #909090">Victoria Falls</span>
