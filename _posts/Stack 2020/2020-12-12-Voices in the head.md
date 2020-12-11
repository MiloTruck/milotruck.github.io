---
title: "Voices in the head [1692]"
tags: [Stack 2020, Forensics]
excerpt: "Forensics"
layout: single
classes: wide
--- 

**Category:** Forensics

## Challenge Description
>We found a voice recording in one of the forensic images but we have no clue what's the voice recording about. Are you able to help?

## Initial Analysis
We are given a WAV audio file. Sometimes, the spectrogram contains text as seen from previous CTF experience. Using Audacity, the spectrogram of the WAV file can be viewed. To open the spectrogram, click the dropdown arrow on the left panel beside the file name.

![](https://i.imgur.com/i092acV.jpg)

`aHR0cHM6Ly9wYXN0ZWJpbi5jb20vakVUajJ1VWI=`

The text found is a base64 text as seen from the variation of letters used and the `=` padding to ensure the length is a multiple of 4. After decoding it (using https://base64decode.org or `base64` tool), we find a pastebin link (https://pastebin.com/jETj2uUb) which contains the text below.

```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++++++++++++++++.------------.+.++++++++++.----------.++++++++++.-----.+.+++++..------------.---.+.++++++.-----------.++++++.
```

This is code written in the brainf*ck programming language, notorious for its minimalism. Running this code on an [online compiler](https://copy.sh/brainfuck/) yields the text `thisisnottheflag`. Welp, looks like a dead end.

## Back to the WAV file
After awhile, due to the challenge title not being sufficiently clear, the following hint was given: `Xiao wants to help. Will you let him help you?`. The word "Xiao" means "crazy" in the Chinese hokkien dialect. The challenge title "Voices in the head" refers to a crazy person and hence Xiao. 

Xiao is a reference to Xiao Steganography. Steganography is a method used for hiding information in files, in this case, WAV files. Using a [Xiao Steganography decoder](https://download.cnet.com/Xiao-Steganography/3000-2092_4-10541494.html), we notice that there is a ZIP file hidden in the WAV file. 

![](https://i.imgur.com/dRBaVrr.png)

Upon attempting to extract the files, we realize that the ZIP file is invalid. When viewed in a hex editor, the file signature is incorrect as it does not correspond to a ZIP file as seen from [this website](https://www.garykessler.net/library/file_sigs.html). For those new to CTFs, all files contain a file signature - a fixed pattern of bytes to begin the file, sometimes called magic bytes.

Edit: The Gary Kessler website may have been taken down. You can access the archived website [here](https://web.archive.org/web/20201111234459/https://www.garykessler.net/library/file_sigs.html).

![](https://i.imgur.com/FYFKg25.png)

![](https://i.imgur.com/rzoqw24.png)

Hence, I suspected that the file was encrypted using the Xiao Steganography password field. But what could the password be?

The only string we've got is `thisisnottheflag` from the brainf*ck code. When this was input into the password field and the ZIP file was extracted, we could finally obtain a valid ZIP file

![](https://i.imgur.com/s7v67TR.png)

![](https://i.imgur.com/llw63mB.png)


## Extracting the ZIP contents
While attempting to extract the ZIP, a password was requested. Since trying the same password (`thisisnottheflag`) doesn't work, looks like we don't have a password this time. What if the password was stored in plaintext, such as in a comment, in the ZIP? Running `strings` would return the following:

```
$ strings xiao.zip
.
.
.
This is it.docx
govtech-csg{Th1sisn0ty3tthefl@g}PK
```

Similar to the previous string, since they tell you that that text is NOT the flag, it's most likely the password for the ZIP. Lo and behold, using `govtech-csg{Th1sisn0ty3tthefl@g}` as the password extracts all the contents of the ZIP. After opening the docx file inside, we obtain the flag!

![](https://i.imgur.com/5xnrpdH.png)

**Flag:** `govtech-csg{3uph0n1ou5_@ud10_ch@ll3ng3}`