---
title: "Only time will tell! [691]"
tags: [Stack 2020, OSINT]
excerpt: "Open Source Intelligence (OSINT)"
layout: single
classes: wide
--- 

**Category:** Open Source Intelligence (OSINT)

## Challenge Description
> This picture was taken sent to us! It seems like a bomb threat! Are you able to tell where and when this photo was taken? This will help the investigating officers to narrow down their search! All we can tell is that it's taken during the day!
> 
> If you think that it's 7.24pm in which the photo was taken. Please take the associated 2 hour block. This will be 1900-2100. If you think it is 10.11am, it will be 1000-1200.
>
> **Flag Example:** `govtech-csg{1.401146_103.927020_1990:12:30_2000-2200}`  
> **Flag Format:** `govtech-csg{lat_long_date_[two hour block format]}`  
> Use this [calculator](https://www.pgc.umn.edu/apps/convert/)!

Maximum attempts: 3 (Removed later in competition)

## Initial Analysis
We are given a jpg image. We are supposed to find the coordinate location (latitude and longitude), the date, as well as a rough time that the image was taken (using a 2h block). 

![](https://i.imgur.com/XhOPlKY.jpg)

Common sense tells us to scan the barcode on the image. Using barcode scanning apps on our phone such as the [Cognex scanner](https://play.google.com/store/apps/details?id=com.manateeworks.barcodescanners&hl=en_SG&gl=US) - which is good for scanning other codes as well - we get the text "25 October 2020". Great! We've got one part of the flag. Just need to convert it to the right form for the challenge. (YYYY:MM:DD as seen from the example given)

> 2020:10:25

The common tool to use when we analyze this image is `exiftool`. This can give us metadata about the image such as time and location. However, time is pretty much out of the question as the file had to be downloaded, likely altering the creation and modification timestamps. 

```bash
$ exiftool osint-challenge-6.jpg
ExifTool Version Number         : 11.88
File Name                       : osint-challenge-6.jpg
File Size                       : 123 kB
File Modification Date/Time     : 2020:12:04 23:58:48+08:00
File Access Date/Time           : 2020:12:09 00:36:23+08:00
File Inode Change Date/Time     : 2020:12:04 23:59:24+08:00
File Permissions                : rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 96
Y Resolution                    : 96
Exif Byte Order                 : Big-endian (Motorola, MM)
Make                            : COViD
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
GPS Latitude Ref                : North
GPS Longitude Ref               : East
Image Width                     : 551
Image Height                    : 736
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 551x736
Megapixels                      : 0.406
GPS Latitude                    : 1 deg 17' 11.93" N
GPS Longitude                   : 103 deg 50' 48.61" E
GPS Position                    : 1 deg 17' 11.93" N, 103 deg 50' 48.61" E
```

## Getting Coordinate Location
At the bottom of the output, we have the GPS latitude and longitude in Degree Minute Seconds (DMS) form. You can convert this form to what the challenge desires (Simply in degrees) on the [calculator website given by the challenge](https://www.pgc.umn.edu/apps/convert/). In DMS, the degrees are in whole numbers and the minutes and seconds are used as "decimals". Placing the latitude and longitude into the calculator, we can get the desired form - Decimal Degrees (DD). There is no need for rounding. The calculator is given by the challenge so we just use whatever precision the calculator gives.

> Latitude: 1.286647
> Longitude: 103.846836

## Finding Time
Now we are left with time. From the image, it looks like the only clue we have for time is the shadow. One method is to use use sun calculations. The second is to use our experience to tell the time. We decided to try the latter as we are convinced that the timing was either from 10-11am or 2-4pm due to the scorching sun. However, we need to find out if the shadow is pointing East or West.

Google Maps shall be our tool of choice. Although this sign points to a familiar place "Speaker's Corner" in Singapore, the coordinates should be used in order to determine its exact location on a big grassy field. 

![](https://i.imgur.com/ASAjEfn.jpg)

We can use background buildings in the photo to determine where the photo is facing. In the photo, we see a uniquely shaped (somewhat triangular) building. This is similar to the shapes of the Furama City Center building in Google Maps.

![](https://i.imgur.com/6pHXdsM.png)

A quick Google search of the building reveals it is the same building. We can further confirm it using street view on the nearby road. We can't really see the background buildings well, but it sure looks like the UOL building in the photo. Anyways, we can see the Speaker's Corner sign in the correct orientation, signalling we are on the right track.

![](https://i.imgur.com/Zl4Bl5Y.png)

Furama City Centre is to the West of the sign. This is because on the web client of Google Maps, North is defaulted to upwards. We thus know that the photographer is facing West. Since the shadow is towards the photographer, it is pointing East, hence, the sun is in the West, concluding the fact that it is in the afternoon.

![](https://i.imgur.com/XhOPlKY.jpg)

Our estimates tell us it is somewhere between 2-4pm. This gives us 3 timing answers

> 1400-1600
> 1500-1700
> 1600-1800 (Highly unlikely)

Since we have 3 attempts, we can try the timings until the flag is accepted. This is "smarter" brute forcing. Rather just narrowing it to a 50/50 without the need to learn sun calculations. The correct timing was 1500-1700. This means the photo was taken awhile after 3pm. This is exactly in the middle of what our initial guess was.

> 1500-1700

**Flag:** `govtech-csg{1.286647_103.846836_2020:10:25_1500-1700}`