---
title: "Walking down a colourful memory lane [992]"
tags: [Stack 2020, Forensics]
excerpt: "Forensics"
layout: single
classes: wide
--- 

**Category:** Forensics

## Challenge Description
>We are trying to find out how did our machine get infected. What did the user do?

## Memory Analysis
We are given a `.mem` file (Memory dump). We can use the premier tool for memory forensics [volatility](https://github.com/volatilityfoundation/volatility). In my 2 weeks of memory forensics experience, I found that as [volatility3](https://github.com/volatilityfoundation/volatility3) is rather new, I prefer to stick to volatility (python2) due to the wealth of available plugins. Note that on my machine, I've set up an alias `vol` for `python vol.py`.

For those who are using volatility for your first time, the format for each command is `vol -f <file> <plugin/command>`

From previous CTFs, I follow a standard procedure (assuming it is a Windows machine which is typical of many CTFs), running `imagescan` then `pslist`. This is a very good starting point as it gives an idea of the machine profile. Think of profiles as a type of Windows machine (ie Windows7, WindowsXP, etc). 
```
$ vol -f forensics-challenge-1.mem imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
.
.
.
```
We can choose the first suggested profile, then run `pslist` to check that the profile chosen works well. Remember to append `--profile=<chosen_profile>` in each volatility command now. `pslist` would return the entire process list.
```
$ vol -f forensics-challenge-1.mem --profile=Win7SP1x64 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
.
.
.
0xfffffa80199e6a70 chrome.exe             2904   2460     33     1694      1      0 2020-12-03 09:10:20 UTC+0000
0xfffffa801a1d5b30 chrome.exe              852   2904     10      170      1      0 2020-12-03 09:10:20 UTC+0000
0xfffffa801998bb30 chrome.exe             1392   2904     10      274      1      0 2020-12-03 09:10:20 UTC+0000
0xfffffa801a91d630 chrome.exe              692   2904     13      225      1      0 2020-12-03 09:10:20 UTC+0000
0xfffffa8019989b30 chrome.exe             1628   2904      8      152      1      0 2020-12-03 09:10:21 UTC+0000
0xfffffa801a84cb30 chrome.exe             1340   2904     13      280      1      0 2020-12-03 09:10:24 UTC+0000
0xfffffa801acbeb30 chrome.exe             1112   2904     14      251      1      0 2020-12-03 09:10:27 UTC+0000
0xfffffa801acd8b30 chrome.exe              272   2904     14      239      1      0 2020-12-03 09:10:27 UTC+0000
0xfffffa801acd1060 chrome.exe             1648   2904     13      227      1      0 2020-12-03 09:10:28 UTC+0000
0xfffffa801acedb30 chrome.exe             3092   2904     13      212      1      0 2020-12-03 09:10:28 UTC+0000
0xfffffa801ad0eb30 chrome.exe             3160   2904     15      286      1      0 2020-12-03 09:10:29 UTC+0000
0xfffffa801ad3cb30 chrome.exe             3220   2904     15      295      1      0 2020-12-03 09:10:30 UTC+0000
0xfffffa801ad3ab30 chrome.exe             3240   2904     13      218      1      0 2020-12-03 09:10:30 UTC+0000
0xfffffa801ad8d060 chrome.exe             3320   2904     13      218      1      0 2020-12-03 09:10:32 UTC+0000
0xfffffa801ad9eb30 chrome.exe             3328   2904     13      231      1      0 2020-12-03 09:10:33 UTC+0000
0xfffffa801addfb30 chrome.exe             3380   2904     13      304      1      0 2020-12-03 09:10:34 UTC+0000
0xfffffa801ad9ab30 chrome.exe             3388   2904     13      283      1      0 2020-12-03 09:10:34 UTC+0000
0xfffffa801ae269e0 chrome.exe             3444   2904     13      231      1      0 2020-12-03 09:10:38 UTC+0000
0xfffffa801ae2e7d0 chrome.exe             3456   2904     12      196      1      0 2020-12-03 09:10:42 UTC+0000
0xfffffa801ae63060 chrome.exe             3568   2904     12      222      1      0 2020-12-03 09:10:44 UTC+0000
0xfffffa801ae89b30 chrome.exe             3584   2904      9      173      1      0 2020-12-03 09:10:45 UTC+0000
0xfffffa801aed8060 notepad.exe            3896   2460      5      286      1      0 2020-12-03 09:10:52 UTC+0000
0xfffffa801aeb5b30 chrome.exe             2492   2904     12      171      1      0 2020-12-03 09:10:58 UTC+0000
0xfffffa801af22b30 chrome.exe             1348   2904     12      171      1      0 2020-12-03 09:10:59 UTC+0000
0xfffffa801af63b30 chrome.exe             3232   2904     12      182      1      0 2020-12-03 09:11:00 UTC+0000
0xfffffa801af9d060 chrome.exe             4192   2904     12      168      1      0 2020-12-03 09:11:02 UTC+0000
0xfffffa801afaf630 chrome.exe             4268   2904     12      171      1      0 2020-12-03 09:11:04 UTC+0000
0xfffffa801afa6b30 chrome.exe             4324   2904     14      180      1      0 2020-12-03 09:11:04 UTC+0000
0xfffffa801afbeb30 chrome.exe             4380   2904     12      179      1      0 2020-12-03 09:11:04 UTC+0000
```

From experience, we can see 2 suspicious processes `notepad` (commonly used as a target in other CTFs) and `chrome` (exceptionally large number of chrome processes). I decided to explore chrome first as it is very suspicious to have such a large number of Google Chrome processes. 

## Analyzing chrome.exe
To analyze a Google Chrome history, we can use the `filescan` and `dumpfiles` plugins, followed by using `sqlitebrowser` to view the chrome history. More can be read up on part 9 in [this writeup](https://medium.com/hackstreetboys/hsb-presents-otterctf-2018-memory-forensics-write-up-c3b9e372c36c). 

Alternatively, we can install the `chromehistory` plugin from https://github.com/superponible/volatility-plugins. If your volatility was compiled from source, you can copy the plugin files into `volatility/volatility/plugins` rather than passing the `--plugins=<directory>` argument. This makes it easier to install plugins though it can get very messy if you wish to uninstall them so I only advise to do this if you really want the convenience of installing plugins which you KNOW work.

Most of the websites here are fluff as one could tell from random Google searches and going to STACK conference website homepage. However, 2 lines caught my attention:
```
$ vol -f forensics-challenge-1.mem --profile=Win7SP1x64 chromehistory
.
.
.
    8 http://www.mediafire.com/view/5wo9db2pa7gdcoc/This_is_a_png_file.png/file        This is a png file.png - MediaFire                                                    3     0 2020-12-03 09:10:50.055213        N/A
    24 http://www.mediafire.com/view/5wo9db2pa7gdcoc/                                   This is a png file.png - MediaFire                                                    3     0 2020-12-03 08:24:50.579952        N/A
```

A PNG file from mediafire. Looking back at the challenge name, we realize that colors could refer to images like this one. 

## Analyzing the PNG
If we look at the PNG - well - you can't really see it as it is tiny. In case the image is too hard to see, I'll describe it: a small line of colored then black pixels. Initially, I thought it was colored text in a terminal. However, after downloading the image, further inspection by viewing image properties showed that it was a 64x1 pixel image.

![](https://i.imgur.com/hosDlXf.png)

After some thought, I noticed that it was a line of colored pixels, followed by a line of black pixels. The RGB values of black is (0,0,0). We can consider the fact that the RGB values of each pixel correspond to ASCII values representing the flag. 

![](https://i.imgur.com/zAMgSnJ.png)

To convert the image to RGB values, one could simple search PNG to RGB and find [this website](https://convertio.co/png-rgb/). Opening the output file in a hex editor or simply running the UNIX `cat` on the it would produce the flag.

However, the real technical term for a similar file is a bitmap (.BMP). An uncompressed bitmap file represents its bits in RGB but in 3 byte [little endian](https://en.wikipedia.org/wiki/Endianness) (BGR instead of RGB) which may make it harder to read. Nonetheless, using a hex editor, one can decode the flag after converting from PNG to BMP as well.

> vogcetc-h{gsm3myr03R_rGdn33ulB}z3

Yet another alternative, if you are more familiar with tools, is to use [zsteg](https://github.com/zed-0xff/zsteg) which is able to produce different steganographic outputs, including lowest significant bit (LSB) and RGB bytes.
```
$ zsteg -a image.png
b8,r,lsb,xy         .. text: "gthsm0_d3B3"
b8,g,lsb,xy         .. text: "oe-g3rRG3lz"
b8,b,lsb,xy         .. text: "vcc{my3rnu}"
b8,rgb,lsb,xy       .. text: "govtech-csg{m3m0ry_R3dGr33nBlu3z}"
b8,bgr,lsb,xy       .. text: "vogcetc-h{gsm3myr03R_rGdn33ulB}z3"
b8,rgb,lsb,xy,prime .. text: "h-csg{0rydGr"
b8,bgr,lsb,xy,prime .. text: "c-h{gsyr0rGd"
b8,r,lsb,XY         .. text: "3B3d_0mshtg"
b8,g,lsb,XY         .. text: "zl3GRr3g-eo"
b8,b,lsb,XY         .. text: "}unr3ym{ccv"
b8,rgb,lsb,XY       .. text: "3z}Blu33ndGr_R30rym3msg{h-ctecgov"
b8,bgr,lsb,XY       .. text: "}z3ulBn33rGd3R_yr0m3m{gsc-hcetvog"
b8,rgb,lsb,XY,prime .. text: "3z}m3mh-c"
b8,bgr,lsb,XY,prime .. text: "}z3m3mc-h"
```

**Flag:** `govtech-csg{m3m0ry_R3dGr33nBlu3z}`