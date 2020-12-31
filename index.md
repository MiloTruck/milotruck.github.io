---
title: "MiloTruck"
layout: splash
hidden: true
header:
  overlay_color: "#000"
  overlay_filter: "0.5"
  overlay_image: /assets/images/Splash Page Header.jpg
  actions:
    - label: "Read More"
      url: /About/
excerpt: >
  Hi, I'm MiloTruck. This is my blog with posts about my competitions and projects. Most of my posts and writeups are about CTFs, Competitive Programming or Data Science/Artificial Intelligence stuff. I might occasionally write about interesting life experiences too...  
feature_row:
  - title: "Cybersecurity"
    excerpt: "Contains mostly CTF writeups and experiences. I also occasionally post about Cybersec experiences and resources I find helpful."
    url: /Cybersecurity/
    btn_label: "Explore"
    btn_class: "btn--primary"
  - title: "Posts"
    excerpt: "Recent posts written by me. Mostly contains CTF writeups."
    url: /Posts/
    btn_label: "Explore"
    btn_class: "btn--primary"
  - title: "Achievements"
    excerpt: "List of achievements and awards I have attained from participating in competititons." 
    url: /About/
    btn_label: "Explore"
    btn_class: "btn--primary"
feature_row2:
  - title: "Projects"
    excerpt: 'These are the projects I embark on during my free time. Most of them are random ideas I find interesting or useful.'
    url: /Projects/
    btn_label: "Explore"
    btn_class: "btn--primary"
    image_path: /assets/images/Projects.png
---

{% include feature_row id="intro" type="center" %}

{% include feature_row %}

{% include feature_row id="feature_row2" type="left" %}

{% include feature_row id="feature_row3" type="right" %}
