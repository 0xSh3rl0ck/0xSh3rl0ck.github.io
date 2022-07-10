---
title: "Cyber Defenders: Pwned DC"
classes: wide
header:
  teaser: /assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/1.PNG
ribbon: Black
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

# #1	What is the OS Product name of PC01?

We can solve this question in many ways: easy one that we can search for the OS Product name in the AD-ACLs json files which is provided with the challenge in the `20211122102526_computers.json` file.but first we can use online formatter to make it easy to read, i used this [website](https://jsonformatter.curiousconcept.com/#).

[![1](assets/images/CTF-WriteUp/Cyber-Defenders-Pwned_DC/2.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture11.PNG)


