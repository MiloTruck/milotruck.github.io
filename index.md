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
    btn_label: "Learn More"
    btn_class: "btn--primary"
  - title: "Artificial Intelligence, Data Science"
    excerpt: "Includes DS/AI related projects and Kaggle competitions. I also write about the competitions I have participated in."
    url: /Data-Science-and-AI/
    btn_label: "Learn More"
    btn_class: "btn--primary"
  - title: "Competitive Programming"
    excerpt: "Consists of CP competitions and resources. I might also post solutions for problems on Hackerrank and Kattis."
    url: /Competitive-Programming/
    btn_label: "Learn More"
    btn_class: "btn--primary"
feature_row2:
  - title: "Projects"
    excerpt: 'These are the projects I embark on during my free time. Most of them are random ideas I find interesting or useful.'
    url: /Projects/
    btn_label: "Explore"
    btn_class: "btn--primary"
    image_path: /assets/images/Projects.png
feature_row3:
  - title: "Achievements"
    excerpt: 'Over the years of competing in various STEM-related competitions, these are the achievements I have attained, with many more to come...'
    image_path: /assets/images/Achievements.jpg
    url: /About/
    btn_label: "Explore"
    btn_class: "btn--primary"
---

{% include feature_row id="intro" type="center" %}

{% include feature_row %}

{% include feature_row id="feature_row2" type="left" %}

{% include feature_row id="feature_row3" type="right" %}
