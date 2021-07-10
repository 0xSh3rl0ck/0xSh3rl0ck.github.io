---
title: "CyberTalents - Monaliza"
classes: wide
header:
  teaser: /assets/images/CTF-WriteUp/Monaliza/mona-lisa-c-1503-1519.jpg
ribbon: MidnightBlue
description: "Monaliza is a Digital Forensics Medium challenge. From the CyberTalent platform."
categories:
  - CTF-WriteUp
toc: true
---

1- we will unzip the folder
we will notice that the extension of the extracted file is **monaliza.mem**

2- what is **.mem** extension ? 
it's image of memory dump , so we will use this awesome tool [Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) to investigate it.

3- we will use **imageinfo** to see the suggested profile of the memory dump
as we see : 
[![2](/assets/images/CTF-WriteUp/Monaliza/2.PNG)](/assets/images/CTF-WriteUp/Monaliza/2.PNG)

it's WinXPSP2x86.

4- then we will see the processes that were opened while the memory aquisition with **pslist**
as we see : 
[![2](/assets/images/CTF-WriteUp/Monaliza/3.PNG)](/assets/images/CTF-WriteUp/Monaliza/3.PNG)
That's many processes to investigate 

![LOL](https://media.giphy.com/media/xU9TT471DTGJq/giphy.gif)

but wait don't forget that the name of the challenge is **Monaliza** , so we will just see mspaint.exe 

![:)](https://media.giphy.com/media/ZC0ATzzJnKqn2SNDHR/giphy.gif)

5- then we will dump the process with memdump -p 800 (which is process id) -D (where you want to dump it)
as we see : 
[![4](/assets/images/CTF-WriteUp/Monaliza/4.PNG)](/assets/images/CTF-WriteUp/Monaliza/4.PNG)
the dumped process will be with extension .dmp

6- then we will use **Gimp** tool to open it but first we need to change the extension to .data to open the raw data with **Gimp**.
after playing with the offset too much time :(.                                               

![:"](https://media.giphy.com/media/d2lcHJTG5Tscg/giphy.gif)

then i find it 

[![5](/assets/images/CTF-WriteUp/Monaliza/5.PNG)](/assets/images/CTF-WriteUp/Monaliza/5.PNG)

![:)](https://media.giphy.com/media/MFDnO8ulIE5dptAaFz/giphy.gif)

then we will rotate the image and we will get the flag :), i'll not write the flag to try it and learn without just copying it :).

Hope You Enjoy This. 

![.](https://media.giphy.com/media/1xucXbDnMIYkU/giphy.gif)

