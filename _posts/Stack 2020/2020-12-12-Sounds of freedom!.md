---
title: "Sounds of freedom! [750]"
--- 

**Category:** Open Source Intelligence (OSINT)

## Challenge Description
>In a recent raid on a suspected COViD hideout, we found this video in a thumbdrive on-site. We are not sure what this video signifies but we suspect COViD's henchmen might be surveying a potential target site for a biological bomb. We believe that the attack may happen soon. We need your help to identify the water body in this video! This will be a starting point for us to do an area sweep of the vicinity!
>
> **Flag Format:** govtech-csg{postal_code}

## Initial Analysis
We are given a video and asked to find the location of the waterbody. I have included snapshots of the videos for analysis:

Analysis of Snapshot 1
* Bus Stop alongside the road
* Housing estate has black _pillars_ outside the windows
* Sounds of military aircrafts flying overhead

![](https://i.imgur.com/DbtLpkY.jpg)

Analysis of Snapshot 2
* Light blue HDBs on the opposite side

![](https://i.imgur.com/LdBtUWw.jpg)

## Thought process and Solution
The details from the video should be sufficient to identify the place when we see it on Google Maps. However, looking at all water bodies in Singapore would be too time consuming. Hence, I looked for ways to narrow down possible waterbodies.

The title _Sounds of Freedom_ seems to refer to the miltary aircrafts flying, which led me to think the waterbody was near Paya Lebar Air Base. This immediately narrowed down the search to three locations:
* Punggol Park
* Tampines Quarry
* Bedok Resevoir

![](https://i.imgur.com/pJpDH5q.jpg)

We can use Google Street View to look at bus stops near these locations. Keep in mind there should be a housing estate near the bus stop and HDBs opposite the waterbody. Eventually, I found the bus stop shown in the video, located at [Punggol Park](https://www.google.com.sg/maps/@1.3759369,103.8997028,3a,75y,269.45h,80.36t/data=!3m6!1e1!3m4!1stOiJmHtDMsAV1kRpBsCiPw!2e0!7i16384!8i8192). A quick search on Google Maps tell us the address is `Hougang Ave 10, Singapore 538768`.

**Flag:** `govtech-csg{538768}`