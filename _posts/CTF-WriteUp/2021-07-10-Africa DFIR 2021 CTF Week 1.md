---
title: "Africa DFIR CTF Week 1"
classes: wide
header:
  teaser: /assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture.PNG
ribbon: Black
description: "This is Week 1 from Africa DFIR CTF, which talks about Disk Image Forensics."
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

here we talk about IPv4 of FTP server so first let's see what app the user use. so let's go to installed Programs in autopsy.   

[![4](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture4.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture4.PNG)

as we see here he used FileZilla Client 3.53.1 v.3.53.1. In the case of FileZilla our source of evidence is the XML configuration files that FileZilla leaves behind in the %user%\appdata\roaming\filezilla directory(FileZilla Artifacts).as we see here : 

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

here we can use two ways one to go to exif metadata (Autopsy Ingest Module) to find the photo or to use keyword search :

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

[![20](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture20.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture20.PNG)

when we see `port scan` so we can guess that he use like nmap or other tool to make port scan. so let's see. we can check installed programs in autopsy to see what apps did the suspect installed to make port scan : 

[![21](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture21.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture21.PNG)

like we guessed that the user installed and used nmap to make port scan.so to get the command that the user entered to make port scan we can check `Command History in PowerShell`. By default, the PowerShell in Windows 10 saves the last 4096 commands that are stored in a plain text file located in the profile of each user `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`, and here we can get the flag.

[![100](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Untitled.png)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Untitled.png)

# Copy Location:

[![22](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture22.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture22.PNG)

first i made a keyword search to find the photo.

[![23](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture23.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture23.PNG)

then we will use any online tool to extract metadata or we can use exiftool.

[![24](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture24.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture24.PNG)

After we see LG Electronics so what come to my mind are `ShellBags` are a popular artifact in Windows forensics often used to identify the existence of directories on local, network, and removable storage devices. ShellBags are stored as a highly nested and hierarchal set of subkeys in the UsrClass.They are are a set of subkeys in the UsrClass.dat registry hive of Windows 10 systems. The shell bags are stored in both NTUSER.DAT and USRCLASS.DAT: 
  NTUSER.DAT: HKCU\Software\Microsoft\Windows\Shell
  USRCLASS.DAT: HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell
in Autopsy we can go to shellbags and get the flag `DCIM` : 

[![25](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture25.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture25.PNG)

# Hash Cracker:

[![26](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture26.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture26.PNG)

by using google we can identify the hash type which is `NTLM` Hash you can read about it [Here](https://aio-forensics.com/recover-windows-passwords-Forensics).

we can use two ways to bruteforce the first one with hashcat , the second one with any online tool the easy way ^^.

[![28](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture28.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture28.PNG)

# User Password:

[![27](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture27.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture27.PNG)

what come to my mind when i saw `Windows login password` ?
that we need to go to Registry artifacts in a Windows system because it functions as a database that stores various system configurations every second `HKEY_CURRENT_CONFIG: Stores information from the hardware profile that is being used on the current system`.

[![29](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture29.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture29.PNG)

 what we need to extract is `HKEY_LOCAL_MACHINE \ SAM` and `HKEY_LOCAL_MACHINE \ System ` .After Extract them i will use [mimikatz](https://github.com/gentilkiwi/mimikatz/wiki) to get the user hash from extracted Registry Hives.

 the command i used : [![30](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture30.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture30.PNG)

 the user NTLM hash : 

[![31](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture31.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture31.PNG)

then we will crack the hash i used the same [online tool](https://www.onlinehashcrack.com/) to crack it we can also use hashcat or john the ripper.then we will get the flag :).

[![32](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture32.PNG)](/assets/images/CTF-WriteUp/DFIR-WEEK-1/Capture32.PNG)

useful resource : 
[windows-forensic-analysis](https://www.sans.org/blog/new-windows-forensics-evidence-of-poster-released/)

i hope you enjoy this :) , if you have any question contact me.



 
