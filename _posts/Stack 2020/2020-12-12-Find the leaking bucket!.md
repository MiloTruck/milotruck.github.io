---
title: "Find the leaking bucket! [978]"
--- 

**Category:** Cloud

## Challenge Description

> It was made known to us that agents of COViD are exfiltrating data to a hidden S3 bucket in AWS! We do not know the bucket name! One tip from our experienced officers is that bucket naming often uses common words related to the company’s business.
> 
> Do what you can! Find that hidden S3 bucket (in the format “word1-word2-s4fet3ch”) and find out what was exfiltrated!

There doesn't seem to be any obvious way to find out the leaking bucket. So we decided to brute force to find out. With only 2 words to guess, brute force doesn't seem unreasonable.

![](https://i.imgur.com/H499XQt.png)


Visiting the company site, we are greeted with a word cloud. The most obvious solution was to use these words in the word cloud, however, we couldn't find the bucket with that alone (if only it were that simple...)

At this stage, we thought we needed to come up with our own words. To facilitate this I uploaded the script to our team EC2 instance which we set up in preparation for this ctf. There, we just kept adding words that we thought of including text from images on the website. With the new wordlist, we ran the script again. 

This allowed us to find the bucket: `think-innovation-s4fet3ch`
While the script was running, we managed to confirm with admin that all words could be found on the website. But by then, we had already found the bucket. This is thanks to one of our team members deciding to add in words from the quote by Steve Jobs. 

Using `aws cli`, we can easily view the contents of the bucket with the  command:
`aws s3 ls s3://think-innovation-s4fet3ch`

For which we get the following output
`2020-11-17 23:59:54     273804 secret-files.zip`

Promising... Seems like we found the bucket. Again using aws-cli, we download the files with
`aws s3 cp s3://think-innovation-s4fet3ch/secret-files.zip ./`

But our job is not done yet. When we try to unzip the files, we are prompted for a password (nani???). Immediately we thought of cracking the zip. With a few simple commands, we already got JTR brute forcing the zip. But after running it for a few second, we already sorta knew this wasn't the solution. If JTR wasn't able to insta-crack it with rockyou.txt, it's quite safe to say the password is strong. However, we weren't out of options just yet. While attempting to unzip, we also see that there are 2 files in the zip. 

```
ERROR: Wrong password : flag.txt
ERROR: Wrong password : STACK the Flags Consent and Indemnity Form.docx
```

Why is there an extra document there??? Looks like it was left there on purpose. It is a file that participants under 18 must fill up to join the CTF, we encountered it during registration, and we knew we could download a copy. So we know

1. The zip contains 2 files with both encrypted
2. The password is relatively resistant to brute force
3. We have an unencrypted copy of one of the files

Surely, this having access to one of the files must help right? And indeed it does. Knowing the plaintext of one of the files makes the zip vulnerable to a plaintext attack. We can use `pkcrack` to perform this attack. For this to happen, we also need to ensure that our plaintext is compressed in the same way as the encrypted zip. Initally, we tried to use Ubuntu default archive manager, and that didn't work. Next we tried zipping it from the cmdline using:
`zip -r known.txt STACK\ the\ Flags\ Consent\ and\ Indemnity\ Form.docx`

Within a few seconds, pkcrack gives us an unencrypted zip file which contains our `flag.txt`.

**Flag:** `govtech-csg{EnCrYpT!0n_D0e$_NoT_M3@n_Y0u_aR3_s4f3}`