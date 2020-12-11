---
title: "Hunt him down! [970]"
tags: [Stack 2020, OSINT]
excerpt: "Open Source Intelligence (OSINT)"
layout: single
classes: wide
--- 

**Category:** Open Source Intelligence (OSINT)

## Challenge Description
> After solving the past two incidents, COViD sent a death threat via email today. Can you help us investigate the origins of the email and identify the suspect that is working for COViD? We will need as much information as possible so that we can perform our arrest!
>
> **Example Flag:** `govtech-csg{JohnLeeHaoHao-123456789-888888}`  
> **Flag Format:** `govtech-csg{fullname-phone number[9digits]-residential postal code[6digits]}`

## Analysing the Email
We are given an eml file. Opening it in a text editor reveals the following. 
```
X-Pm-Origin: internal
X-Pm-Content-Encryption: end-to-end
Subject: YOU ARE WARNED!
From: theOne <theOne@c0v1d.cf>
Date: Fri, 4 Dec 2020 21:27:07 +0800
Mime-Version: 1.0
Content-Type: multipart/mixed;boundary=---------------------9d9b7a65470a533c33537323d475531b
To: cyberdefenders@panjang.cdg <cyberdefenders@panjang.cdg>

-----------------------9d9b7a65470a533c33537323d475531b
Content-Type: multipart/related;boundary=---------------------618fd3b1e5dbb594048e34eeb9e9fcdb

-----------------------618fd3b1e5dbb594048e34eeb9e9fcdb
Content-Type: text/html;charset=utf-8
Content-Transfer-Encoding: base64

PGRpdj5USEVSRSBXSUxMIEJFIE5PIFNFQ09ORCBDSEFOQ0UuIEJFIFBSRVBBUkVELjwvZGl2Pg==
-----------------------618fd3b1e5dbb594048e34eeb9e9fcdb--
-----------------------9d9b7a65470a533c33537323d475531b--
```

The base64 decodes to a death threat which doesn't have much importance. As for the rest of the email, not much information can be traced to the sender. However, we do know the domain of the sender's email address - `c0v1d.cf`.

## Tracing the Domain
Initially, we tried to use a DNS lookup site, namely [https://securitytrails.com/](https://securitytrails.com/), to search up the domain but to no avail. We soon hit a dead end as it returned nothing.

Pro tip: If you are stuck on a CTF challenge, come back to it an hour or two later. That's exactly what we did.

Using a [different DNS lookup site](https://dnschecker.org/all-dns-records-of-domain.php?query=c0v1d.cf&rtype=ANY), we found a TXT record:
`user=lionelcxy contact=lionelcheng@protonmail.com`

## Stalking Lionel Cheng
Googling his email gives us his [LinkedIn account](https://sg.linkedin.com/in/cheng-xiang-yi-0a4b891b9). We now know his full name.

> Lionel Cheng Xiang Yi

Googling his userid `lionelcxy` then returns his [Instagram](https://www.instagram.com/lionelcxy/) and [Carousell](https://www.carousell.sg/lionelcxy/) accounts.

## Retrieving Phone Number

Now we just need his phone number. We turn to carousell to look for it. Carousell is a marketplace used mainly in Singapore. Having used the app before, we knew that it was not uncommon for users to put their phone number there for those that prefer to communicate through other mediums rather than the built in carousell chat. 

Visiting his profile, we see a listing for a Playstation 1. And in the product description, we find his phone number. 
![](https://i.imgur.com/BVfJ36z.png)

## Finding Location

From his instagram, there are 2 posts on his account. First is him sharing his bike ride recorded using the Strava app. 
  
![](https://i.imgur.com/C41IAxj.png)
  
And the most recent post is of a street hawker stall. More important than the picture is the location geotag which is at Lau Pa Sat a 24 hour market located at Raffles. 
  
![](https://i.imgur.com/Vzf6i4V.png)
  
We go on further to inspect his strava profile. Being avid runners ourselves (totally), we find his profile using the strava app and we see another one of his rides with a clue to where he stays.  
  
![](https://i.imgur.com/zahOKX1.png)

Using these pieces of information, we sort of know what he did. 
1. He went for a bike ride
2. He got hungry and wanted food
3. Initially wanted to go to Social Space at his block, but it was closed
4. Went to Lau Pa Sat which is close to his home to eat

Googling the location of Social Space we see that there are 2 branches.
  
![](https://i.imgur.com/NPYQ5rF.png)
  
However we also know that Lau Pa Sat is just a few minutes away. Hence it is more likely that he was referring to the branch at Marina One rather than the one at Outram. Now we have our postal code: 018925. Our final flag is:

**Flag:** `govtech-csg{LionelChengXiangYi_963672918_018925}`