---
title: "Can you trick OrgX into giving away their credentials? [2000]"
--- 

**Category:** Social Engineering

## Challenge Description
>With the information gathered, figure out who has access to the key and contact the person

## Finding the Target
Since we need to contact a person, it's most likely a phone number or email.

A quick note on sending emails during CTFs:
In the [wise words of Sarah Miller](https://twitter.com/scba/status/1335987654253395972), "First rule of OSINT: if the subject discovers that you're investigating them, you've probably failed". Do NOT use your own email address to send the email. Instead, use temporary email sites such as https://www.guerrillamail.com/compose. For this challenge, we attempted to use such temporary emails, however, we suspect that due to black/whitelists, there was no reply. An alternative is to use a burner email address which you do not use for anything else. Now back to the challenge.

From the previous OSINT challenge "[Who are the possible kidnappers?](#Who-are-the-possible-kidnappers?)", we identified multiple email addresses, including `ictadmin@korovax.org`. When sending an email to most Korovax emails such as Sarah Miller, we are replied with "Thank you for trying". This is NOT the endpoint. It is to tell you that it is a dead end. Afterall, there is no flag.

When sending any email to ictadmin, we are replied with "Almost got it, missing something". This means we are closer and that we need to have something in our email that ictadmin "wants".

## Sending the Correct Email
Recall that in the previous challenge, on https://csgctf.wordpress.com/never-gonna/, the first letter of each line in list of words forms "Rickroll". This is a [reference](https://knowyourmeme.com/memes/rickroll) to the song "Never Gonna Give You Up" by Rick Astley.

Since the website tells us we need to "include" the keywords, we can basically spam a large amount of related text. Having a short amount of time left to the end of the CTF, we spammed as much related text including the full music video name, the artist, song lyrics and Youtube link. We also included the words "Rickroll" and "Rick roll". 

![](https://i.imgur.com/sblgpW9.jpg)

The bot then sends the flag to us with a hint for the next social engineering challenge which we had no time to do.

![](https://i.imgur.com/8r8AIHi.jpg)

After the CTF, we proceeded to try shrinking our "payload" to find the right answer. The bot was specifically looking for the word "Rickroll".

**Flag:** `govtech-csg{CE236F40A35E48F51E921AD5D28CF320265F33B3}`