---
title: "COVID's Communication Technology! [984]"
--- 

**Category:** Internet of Things (IoT) 

## Challenge Description
> We heard a rumor that COVID was leveraging that smart city's 'light' technology for communication. Find out in detail on the technology and what is being transmitted.

## Initial Analysis
We are given a `.logicdata` file. After some research, we find that it is a capture output from a Saleae logic analyzer. Essentially, the deivce logs the output of digital/analog pins.

From the challenge description, we know that it is a communication between 2 devices.

Opening the file in the [Saleae Logic Analyzer software](https://support.saleae.com/logic-software/legacy-software/latest-stable-release-download) (hence forth referred to as Saleae), we find that only a single channel/wire is used to transmit data. Note: for `.logicdata` files, only Saleae version 1 can be used.

![](https://i.imgur.com/rbRSi3Z.png)

## About Communication Protocols
If you are only concerned with the solution and already have some basic knowledge of hardware protocols, feel free to skip this section.

Since this challenge is in the IoT category, I figured I should provide a brief background about communication protocols. In order for 2 devices to send data to each other, a protocol has to be established, similar to typical network transmission protocols, but at a hardware level. Usually, the data line is digital (0 or 1). This is true for this challenge as the data being sent is "light communication".

Examples of common protocols are Serial UART and I2C (pronounced I-squared-C). You can read up on them on your own. But most of them have a pretty standard format: header, address (if more than 2 devices), message length, message. This forms the basis of my initial solution. 

Coming from a robotics background, I am familiar with hardware protocols, even [coding one based off the I2C protocol recently](https://github.com/jloh02/SICC). I will discuss 2 key ideas that are seen in many protocols: Clocks and packet structures.

In every data transmission, in order to differentiate multiple consecutive bits of the same value (e.g. `1111`) a clock is usually established. In systems with more than 1 wire, the clock line (SCL in I2C or CLK) alternates between 0 and 1. Since the system given uses 1 wire, there must be a fixed clock rate, making it easier to read our data as we do not have to worry about rising and falling edges on our clock line.

There is also typically a fixed packet structure. In I2C, it is `<packet header><address><length><data>`
 - The header can simply be a HIGH signal to start the data transmission
 - Addresses are used in systems with multiple devices
 - Length is the string length of the data. Alternatively, some systems may prefer a fixed packet length or a terminator (fixed string to determine end of sequence)

## My Initial Solution
If you are uninterested in my failed almost unimportant attempts, skip this section. However, note that skipping this section also assumes you have used the Saleae software before or can figure it out on your own.

Of course, the easiest way to start this challenge is to try all the different analyzers (right panel). That didn't work. So I proceeded to analyze the data packets manually.

As seen below, each packet begins with a long HIGH, a long LOW, followed by a sequence of HIGHs and LOWs of fixed width (clock timing has been established). It is interesting to note how a HIGH also has LOWs beside it which does not occur in many protocols.

![](https://i.imgur.com/XDPH9nv.png)

Scrolling in on each HIGH reveals that it is an oscillating signal, making it even harder for certain analyzers to read.

![](https://i.imgur.com/AazRe8w.png)

Thus, I decided to write a python script to parse the data. The data can be exported to via `options > Export data`. I assumed the following to be the headers (including addresses): `<long HIGH><long LOW>1111111110101010101010101`. Anything after would form the data. I then interpreted the data. For the above image, it would've been `101011101010110111`. I also assumed a fixed packet length, padding each packet to a multiple of 8 bits. However, converting this to ASCII didn't work, even if I used a 7-bit ASCII instead. 

It was at this point I realized my approach was probably wrong. The challenge must be telling something else.

## The Real Solution
It dawned upon me that light protocol could refer to an infrared light protocol (NEC IR). I googled about the NEC IR protocol and out came this image.

![](https://i.imgur.com/l32xeKe.png)

Bingo! This looks EXACTLY like what we are given! 

In each NEC IR packet, the value of each bit is determined by the time between 2 HIGHs. A long 9ms HIGH and 4.5ms LOW signals the start. Followed by the address and its logical inverse, and then the data and its logical inverse for verification.

The Saleae Logic Analyzer software does not officially support the NEC IR protocol so if I wanted to use the software's analyzer, I would've had to download the Saleae SDK and import a [library](https://github.com/LiveOverflow/NECAnalyzer). I also figured that since each "HIGH" contains multiple oscillations of HIGHs and LOWs, this may introduce errors. Instead, we can export the data to a CSV and use a Python script to decode the data whilst ignoring the "noise".

![](https://i.imgur.com/AazRe8w.png)

In addition, we notice that the last quarter of the data packets given are not an exact logical inverse of the 3rd quarter. This means the data in our capture does not exactly correspond to the original NEC IR specifications. So perhaps using a script to parse this data is simpler than trying to make an existing analyzer work.

![](https://i.imgur.com/XDPH9nv.png)

Using the Python script below, the bits of the data can be extracted including the headers and addresses. Thresholds for headers and timings between bits could be empirically derived from Saleae in case the transmission does not directly correspond to the original NEC IR specifications. 

```python
import pandas as pd

# Empirically determined timings for 0s and 1s
zeroTime=0.0005698 
oneTime=0.001725

df = pd.read_csv('raw.csv')

outstr = ''
prevT = 0
prevX = 0
prevOne=0
first = True
threshold = (zeroTime+oneTime)/2
print "Threshold:",threshold

for index, row in df.iterrows():
	t = row['t']-prevT
	if t > 0.0001: #Ignoring noise where gap between 2 HIGHs less than 0.1ms
		if t > 0.5: #If gap between 2 HIGHs is more than 500ms, start next packet (ie next line in output string)
			if not first: outstr += '\n'		
			first = False	
		else:	#When a valid HIGH is detected, determine the value of the bit based on the time between the two
			if prevX==0:
				outstr+= '1' if t>threshold else '0'
	prevT = row['t']
	prevX = row['x']

#Save output string to file
with open('out.txt','w') as f:
	f.write(outstr)
```

The output of the above script produces a text file including headers and addresses. The block below only contains one of 6 repeated instances - the message was sent 6.5 times.
```
100000000111111110000000000000000
100000000111111110000000000000000
100000000111111110110011101101111
100000000111111110111011001110100
100000000111111110110010101100011
100000000111111110110100000101101
100000000111111110110001101110011
100000000111111110110011101111011
100000000111111110100001101010100
100000000111111110110011001011111
100000000111111110100100101010010
100000000111111110101111101001110
100000000111111110100010101000011
100000000111111110101111100110010
100000000111111110011000001000000
100000000111111110011000000100001
100000000111111110101111101111101
```

Since the address and its logical inverse is consistent throughout (only 1 destination address), the header, address and inverse address can be removed. I used a simple find and replace in a text editor to remove `10000000011111111`. The first 2 lines can also be excluded since they are null bytes.
```
0110011101101111
0111011001110100
0110010101100011
0110100000101101
0110001101110011
0110011101111011
0100001101010100
0110011001011111
0100100101010010
0101111101001110
0100010101000011
0101111100110010
0011000001000000
0011000000100001
0101111101111101
```

Copying the above text into a [binary to ASCII converter](https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html), we obtain the flag `govtech-csg{CTf_IR_NEC_20@0!_}`, except for an extra '_' which could've been added to make the string a multiple of 2 characters.

**Flag:** `govtech-csg{CTf_IR_NEC_20@0!}`