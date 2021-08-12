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

we will use of course [volatility3](https://github.com/volatilityfoundation/volatility3). also this will help us to fix the messy output formatting of volatility 3 (https://twitter.com/vinopaljiri/status/1401724169847545857).

# Be Brave:

[![1](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture1.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture1.PNG)

here in the description he talk about process ID for application brave. In computing, the process identifier (a.k.a. process ID or PID) is a number used by most operating system kernels—such as those of Unix, macOS and Windows—to uniquely identify an active process. This number may be used as a parameter in various function calls, allowing processes to be manipulated, such as adjusting the process's priority or killing it altogether.

in volatility there is a plugin called windows.pslist.PsList which list all the process with the PID which we need for the flag.

[![1](/assets/images/CTF-WriteUp/DFIR-WEEK-2/Capture2.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture2.PNG)

Flag : <span style="color: #909090">4856</span>