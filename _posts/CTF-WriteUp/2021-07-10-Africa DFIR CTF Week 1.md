---
title: "Africa DFIR CTF Week 1"
classes: wide
header:
  teaser: /assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture.PNG
ribbon: Black
description: "This is Week 1 from Africa DFIR CTF, which talks about Forensic Disk Image."
categories:
  - CTF-WriteUp
toc: true
---
<span style="color: #909090">Category: Digital Forensics</span>

> Challenge : [Week 1](https://archive.org/download/africa-dfirctf-2021-WK01)

# Deleted:

[![1](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture1.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture1.PNG)

As we see from the name of the challenge "Deleted". so what we will search for will be in Recycle Bin (artifact). in my case i will use autopsy, you can use any other tool. if we go to Recycle bin we will find one txt file that deleted and here's the flag : 

[![2](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture2.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture2.PNG)

# Server Connection:

[![3](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture3.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture3.PNG)

here we talk about IPv4 of FTP server so first let's see what app the user use.so let's go to installed Programs in autopsy.  

[![4](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture4.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture4.PNG)

as we see here he used FileZilla Client 3.53.1 v.3.53.1. In the case of FileZilla our source of evidence is the xml configuration files that FileZilla leaves behind in the %user%\appdata\roaming\filezilla directory(FileZilla Artifacts).as we see here : 

[![5](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture5.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture5.PNG)

# Suspect Disk Hash:

[![6](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture6.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture6.PNG)

here we will use [FTK Imager](https://accessdata.com/products-services/forensic-toolkit-ftk/ftkimager) to import the disk images and calculate the hash of them.


