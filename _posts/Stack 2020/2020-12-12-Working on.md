---
title: "What is he working on? Some high value project? [790]"
tags: [Stack 2020, OSINT]
excerpt: "Open Source Intelligence (OSINT)"
layout: single
classes: wide
--- 

**Category:** Open Source Intelligence (OSINT)

## Challenge Description  
> The lead Smart Nation engineer is missing! He has not responded to our calls for 3 days and is suspected to be kidnapped! Can you find out some of the projects he has been working on? Perhaps this will give us some insights on why he was kidnapped…maybe some high-value projects! This is one of the latest work, maybe it serves as a good starting point to start hunting.
> 
> Flag is the repository name!
> 
> Developer's Portal - STACK the Flags
 
Opening the link provided, there is nothing that stands out at first glance. Since the flag is a repository name, we know we have to find some sort of clue that is related. Perhaps there is something we can find in the page source. 

After slowly analyzing the page source, we find a html comment left by the devs.

```html
<a href="https://ctf.tech.gov.sg/">
  <h3 style="text-align: center;">Check out STACK the Flags here!</h3>
</a>

<!-- Will fork to our gitlab - @joshhky -->

    <p>
      <em>
        Last updated 04 December 2020
      </em>
    </p>
  </div>
</div>
```

Hmm... Let's follow the path and search for @joshhky on gitlab. We can view his profile on gitlab using this [link](https://gitlab.com/joshhky). We can confirm that we are on the right path as we see several projects with "KoroVax" in them, suggesting that this user was indeed created for the purpose of the CTF. 

At this stage, we viewed all the repositories and projects he created/imported trying to find any clues. However, majority of them were empty. The only anomaly out of his entire activity was the commit which contained changes in the project README. We can  
click on the commit ID to view more details about it. 

![](https://i.imgur.com/mlINEyj.png)

Upon closer inspection, we see that in the Todo, there is a point about how not all repositories should be public. From this, we can guess that the repository that we are searching for is private. However, just above that, there is also another point which notes that Josh (our target) is in charge of `krs-admin-portal`. This seems suspicious. Perhaps it may be a repository name? No harm trying right?

After wrapping it in the flag format, we try to submit the flag and... it was correct after all :)

**Flag:** `govtech-csg{krs-admin-portal}`