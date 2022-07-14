---
title: "Cyber Defenders: Pwned DC"
classes: wide
header:
  teaser: /assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/1.PNG
ribbon: gray
description: "An ActiveDirectory compromise case from Cyber Defenders"
categories:
  - CTF-WriteUp
toc: true
---

<span style="color: #909090">Category: Digital Forensics, Malware Analysis</span>

> Challenge : [Challenge Link](https://cyberdefenders.org/blueteam-ctf-challenges/89)

**Scenario:**
An ActiveDirectory compromise case: adversaries were able to take over corporate domain controller. Investigate the case and reveal the Who, When, What, Where, Why, and How.

**Tools:**
Magnet
FTK
Autopsy


# #1	What is the OS Product name of PC01?

We can solve this question in many ways: easy one that we can search for the OS Product name in the AD-ACLs json files which is provided with the challenge in the `20211122102526_computers.json` file.but first we can use online formatter to make it easy to read, i used this [website](https://jsonformatter.curiousconcept.com/#).

[![2](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/2.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/2.PNG)

another way to find the OS Product name from the registry hive `HKEY_LOCAL_MACHINE\Software`. we can use RegRipper to scan the registry hive and get to us the OS Product name or simply we can use Autopsy Plugins to do that for us.by going to Operating System information in Data Artifact section in Autopsy. we will see the same result.

[![3](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/3.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/3.PNG)

Flag : <span style="color: #909090">Windows 10 Enterprise 2016 LTSB</span>

# #2	On 21st November, there was unplanned power off for PC01 machine. How long was PC01 powered on till this shutdown?

Here he is asking about the time that PC01 was on till the unplanned power off. we can check Windows Event logs to get this info from `\Windows\System32\winevt\Logs\System.evtx` which stores this information, so we can use TurnedOnTimesView to view this information to us. 

[![4](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/4.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/4.PNG)

as we see here there was unplanned power off and the time the PC01 until this unplanned power off is `11:31`.

Flag : <span style="color: #909090">11:31</span>

# #3	Who was the last logged-in user on PC01?

for this question we want to know that last logged-in user we can also find that in Windows Event logs in `\Windows\System32\winevt\Logs\Security.evtx` which store A successful account logon event with event id `4624` but so i will use Event Viewer to get that. by filtering the logs with `4624` we will get this output.

[![5](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/5.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/5.PNG)

there is to many logs so we can filter them by Date and Time also to get the last logged-in user.if we open the last event.we will find the last logged-in user on PC01.

[![6](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/6.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/6.PNG)

Flag : <span style="color: #909090">0xMohammed</span>

# #4	What is the IP address of PC01?

we can get the ip address of PC01 from registry hive `HKEY_LOCAL_MACHINE\SYSTEM` under `\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` so we can use RegRipper to scan the hive and get the answer to us.

[![7](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/7.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/7.PNG)

Flag : <span style="color: #909090">192.168.112.142</span>

# #5	Which port was assigned to man service on PC01?

the services which is running on the pc and assigned ports to it is stored in `Windows/System32/drivers/etc/services` file. so we can open it using any text editor to find the port assigned to man services.

[![8](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/8.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/8.PNG)

Flag : <span style="color: #909090">9535</span>


# #6	What is the "Business.xlsx" LogFile Sequence Number?

First what is MFT ? The MFT is a set of FILE records. Each file of the volume is completely described by one or more of these FILE Records and $LogFile Sequence Number (LSN) changes every time the record is modified. which is stored in the MFT.
Each LSN is a 64-bit number containing the following components: a sequence number and an offset. An offset is stored in the lower part of an LSN, its value is a number of 8-byte increments from the beginning of a log file. This offset points to an LFS structure containing a client buffer and related metadata, this structure is called an LFS record. A sequence number is stored in the higher part, it’s a value from a counter which is incremented when a log file is wrapped (when a new structure is written to the beginning of the circular area, not to the end of this area).
we can get the that using MFTECmd and save the output to csv using command `MFTECmd.exe -f "C:\Temp\SomeMFT" --csv "c:\temp\out"`.
after that we can search for the Business.xlsx file then we will find the LogFile Sequence Number.

[![9](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/9.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/9.PNG)

Flag : <span style="color: #909090">1422361276</span>

# #7	What is the GUID of the C drive on PC01 machine?

