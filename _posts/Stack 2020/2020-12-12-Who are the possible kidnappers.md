---
title: "Who are the possible kidnappers? [1990]"
tags: [Stack 2020, OSINT]
excerpt: "Open Source Intelligence (OSINT)"
layout: single
classes: wide
--- 

**Category:** Open Source Intelligence (OSINT)

## Challenge Description
> Perform OSINT to gather information on the organisation’s online presence. Start by identifying a related employee and obtain more information. Information are often posted online to build the organization's or the individual's online presence (i.e. blog post). Flag format is the name of the employee and the credentials, separated by an underscore. For example, the name is Tina Lee and the credentials is MyPassword is s3cure. The flag will be `govtech-csg{TinaLee_MyPassword is s3cure}`

> Addendum:
> - Look through the content! Have you looked through ALL the pages? If you believe that you have all the information required, take a step back and analyse what you have.
> - In Red Team operations, it is common for Red Team operators to target the human element of an organisation. Social medias such as "Twitter" often have information which Red Team operators can use to pivot into the organisation. Also, there might be hidden portal(s) that can be discovered through "sitemap(s)"?

## Information Gathering
Throughout the CTF, we see 2 organisations - COViD and Korovax. A quick Google search on Korovax reveals 2 similar websites - https://csgctf.wordpress.com/ and http://korovax.org/. By the time we started investing time in this challenge, the addendum hints had been given. Thus, we proceeded to use sitemap and gain information. I shall only put the relevant sites below.

- /never-gonna/
    - Tells us to include "keywords in email". First letter of each line spells "Rickroll". Title of page is "Never gonna" (Irrelevant for this challenge. Used in next challenge)
- /oh-ho/
    - There lies a link to the "secret social media page" http://fb.korovax.org/. And gives us more information about the passowrd that we were looking for.
    - > I forgot my password to our KoroVax social media page.
        > 
        > I think it’s stored on our corporate page with …blue…something….communication…
        > 
        > Cant remember now. Would have to look through my archived tweets
- /2020/10/01/example-post-3/
    - After painfully scrolling through the posts on the website, we manage to find a twitter handle @scba at the bottom of the post. Perhaps this may be our target?


## Exploring "Facebook"
Note: No screenshots for this section as website was taken down before writeup was written.

We find the company's social media at http://fb.korovax.org/. This is likely the attack point as "credentials" are required. We can simply login to the social media by creating a fake account. On the website, a user's profile can be viewed using `http://fb.korovax.org/users/<account_id>`. Since account ids are given in chronological order, we view the first 10 accounts. We can then gain the following information.

- Amanda Lee
    - There are many posts and comments left by her. And among those we can find
        1. The email for IT admin `ictadmin@korovax.org`
        2. Her Instagram @amanda.hidden
        3. Mention of a telegram bot named @DAViD
- Sarah Miller
    - There are many posts by her from about 2 months back. And while they do reveal some information, what stood out more was that there were more recent comments from 2h ago which seemed to be someone "impersonating" her.
    - This helped us confirm that she was probably the target for the challenge
- Other accounts which we forgot
    - A mention of emailing ictadmin@korovax.org and how a specific phrase is required (Irrelevant for this challenge. Used in next challenge)

## Exploring Twitter
The twitter account "@scba" belongs to an actual person "Sarah Miller" who also appears in the Korovax team page. On /oh-ho/ on the Korovax website, we recall her password is "blue...something...communications". Since Sarah Miller is actually a real person, we used a dummy twitter account for this part of the challenge. Apart from not revealing your identity, it also helps to start with fresh twitter feed with her account being the only one we followed. Searching for "blue" on the @scba twitter account, filtering by people we follow, there were only a handful of tweets that were relevant. Amongst those were: https://twitter.com/scba/status/858009339642077186.

> Blue sky communications

This phrase seemed to fit the clue found on the korovax site. Entering this as her password with her email on the fb site allows us to login, confirming the flag.

**Flag:** `govtech-csg{SarahMiller_Blue sky communications}`

## Rabbit Holes and Deadends
Like any CTF writeup, solving the challenge was much harder than what the writeup may suggest. These were some of the rabbit holes and deadends we encountered when we were searching. A lot of these were because we were too impulsive and immediately clicked the secret social media link without reading the rest of the page on /oh-ho/ which is arguably more important than the facebook. And many of such problems were resolved when we decided to ping admin for help. 
 -  One of the most common ways that people accidentally reveal information is probably through pictures which objects in the background may contain crucial information
 -  We assumed that might have been the case for Sarah Miller and we dedcided to serach through all her media posted on twitter
 -  Since the korovax site had a line about keeping about conference speakers, and Sarah Miller herself has spoken in several conferences, we thought that maybe she might've used a personal example in her slides which could contain an old password
 -  This led us to searching through her slides on slideshare
 -  Then there were her cats butters and pixel which we though might contain a clue on her password. Since we couldn't find relevant media on her main twitter account. So we decided to search through her cats' twitters. 
 -  We also looked for the password for the hidden document on the wordpress which we managed to find/guess. It was ouroboros. But unlocking only revealed a sad pepe.
  ![](https://i.imgur.com/9XOSJ0F.png)
 -   We also ventured into challenges that we've yet to unlocked. This included searching for Amanda's Instagram, emailing ictadmin, looking for the telegram bot DAViD, finding korovax on google maps and calling the number. Listening in to one of Amanda's recorded conversations. 

After finishing the challenge, I guess the most important thing we learnt was to know clearly what you're searching for. It reduces search space by a lot. 