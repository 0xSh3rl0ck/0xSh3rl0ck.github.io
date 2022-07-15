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

The GUID Partition Table (GPT) is a standard for the layout of partition tables of a physical computer storage device, such as a hard disk drive or solid-state drive, using universally unique identifiers, which are also known as globally unique identifiers (GUIDs).so we will check the registry to find the GUID of the Drive at registry hive `HKEY_LOCAL_MACHINE\SYSTEM` under `HKEY_LOCAL_MACHINE\SYSTEM\MOUNTEDDEVICES` but it's not correct so let's try another way.

[![10](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/10.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/10.PNG)

i tried another way by checking NTUSER. DAT which is a windows generated file which contains the information of the user account settings and customizations. Each user will have their own NTUSER. so let's check that for 0xMohammed user at `Users\0xMohammed\NTUSER.DAT`.we can use Registry Explorer for analysing it. under this path `\Users\0xMohammed\NTUSER.DAT: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\` that we will look for mounted devices we will find two keys {8cf4cfff-49a3-11ec-910f-806e6f6e6963} and {fad905b3-fb35-4dbd-ab31-a44f022809d2} we will notice that `{fad905b3-fb35-4dbd-ab31-a44f022809d2}` is the right one but let's verify this with another way.

[![11](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/11.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/11.PNG)

we can check Windows Event logs which could use to determine if and when USB devices had been connected to (and disconnected from) the system `Windows\System32\winevt\Logs\Microsoft-Windows-Ntfs%4Operational.evtx` we can use EventViewer to open it and analyse. there is few logs but also we can filter it with EventID: `142` which contains the information that we need about the volume assignment letter and associated GUID and finally we can validate our answer.

[![12](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/12.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/12.PNG)

also we can use tool like USB Forensic Tracker to extract that for us. but first we need to mount the E01 using FTK or Arsenal Image Mounter then we select the drive that we mounted the Disk Image in it and USB Forensic Tracker will scan all offline registry and windows event for us.then we will see the answer under Win 10 Event Log. 

[![13](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/13.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/13.PNG)

Flag : <span style="color: #909090">fad905b3-fb35-4dbd-ab31-a44f022809d2</span>

# #8	What link did the user visit on 2021-11-22 at 19:45:55 UTC?

i used here Magnet to get out the answer for me from `places.sqlite`. which is a proto database of places visited, bookmarks, and attributes for those sites commonly visited by Firefox which is located at `\Users\labib\AppData\Roaming\Mozilla\Firefox\Profiles\2305bdnv.default-release\places.sqlite` if we go to REFINED RESULTS then Google Searches we will find that he searched for `bluedemy.cyberdefenders.org` at 11/22/2021 7:45:55 PM "12-hour clock".

[![14](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/14.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/14.PNG)

# #9	How many bytes were received by firefox?

Here we need to know the bytes the were received by firefox so we need first to know about SRUM which is a diagnostic tool built into Windows to monitor system resource usage. This tool can provide useful forensic information, for example: It can connect a user account to program execution and the amount of data sent or received over a network.The information is stored in the `\Windows\System32\sru\` directory in a file named SRUDB.DAT.The file is in the Windows ESE (Extensible Storage Engine) database format. So the trick is to get the data out and make sense of it. so we will use srum-dump for this task, after we provided the input to the script it will give us the output in a readable format of Excel sheet.then we will navigate to Network Usage Sheet. and search for firefox application then we will find the answer.

[![15](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/15.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/15.PNG)

Flag : <span style="color: #909090">20418287</span>

# #10	What is the folder name where note.txt resides?

when it comes to know what is the folder name of file so we need to know about LNK Files.LNK files are a relatively simple but valuable artifact for the forensics investigator. They are shortcut files that link to an application or file commonly found on a user’s desktop, or throughout a system and end with an .LNK extension. LNK files can be created by the user, or automatically by the Windows operating system. Each has their own value and meaning. Windows-created LNK files are generated when a user opens a local or remote file or document, giving investigators valuable information on a suspect’s activity which one of them is The original path of the file which will give us the answer.so after searching for `note.txt` i found LNK file associated with it at `\Users\administrator\AppData\Roaming\Microsoft\Windows\Recent\note.lnk`. i will use LECmd to analyse the LNK file with command `LECmd.exe -f "location of LNK file"` then we will see the answer.

[![16](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/16.PNG)](/assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/16.PNG)

Flag : <span style="color: #909090">asd</span>

# #11	Which volatility 2 profile should be used to analyze the memory image?

we will use volatility to analyse the memory image, so we will use `imageinfo` plugin to give us the profile. 