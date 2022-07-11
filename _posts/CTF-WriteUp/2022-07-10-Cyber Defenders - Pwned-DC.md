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


