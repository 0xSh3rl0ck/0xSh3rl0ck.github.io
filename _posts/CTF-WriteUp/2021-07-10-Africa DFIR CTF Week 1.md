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

here we will use [FTK Imager](https://accessdata.com/products-services/forensic-toolkit-ftk/ftkimager) to import the disk image 001Win10.E01 and calculate the hash of the disk , then we will find the md5 hash.

[![7](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture7.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture7.PNG)

# Web Search:

[![8](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture8.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture8.PNG)

in this challenge we need first to convert the time to UTC to be easy for us : 

[![9](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture9.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture9.PNG)

then we will go to web history and we will find the flag : 

[![10](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture10.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture10.PNG)

# Possible Location:

[![12](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture12.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture12.PNG)

here we can use two ways one to go to exif metadata to find the photo or to use keyword search :

[![11](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture11.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture11.PNG)

then we can extract the photo from autopsy and use exiftool or any online tool to get the location of the photo :

[![13](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture13.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture13.PNG)

# Tor Browser:

[![14](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture14.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture14.PNG)

Here we will look at tor prefetch artifact under \Windows\Prefetch : 

[![15](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture15.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture15.PNG)

here we can't see run count or last executed that means that the suspect only installed tor but didn't use it :( .

# User Email:

[![18](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture18.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture18.PNG)

here we can go to Web Accounts in autopsy and we will find that the user uses protonmail:

[![16](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture16.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture16.PNG)

so we can next go to Web From Autofill and we will see the username:

[![17](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture17.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture17.PNG)

by that we got the User Email :).

# Web Scanning:

